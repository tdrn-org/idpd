/*
 * Copyright 2025 Holger de Carne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package idpd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/alecthomas/kong"
	"github.com/google/uuid"
	"github.com/tdrn-org/idpd/httpserver"
	"github.com/tdrn-org/idpd/internal/server"
	"github.com/tdrn-org/idpd/internal/server/database"
	"github.com/tdrn-org/idpd/internal/server/userstore"
	"github.com/tdrn-org/idpd/internal/server/web"
	"github.com/tdrn-org/idpd/oauth2client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const shutdownTimeout time.Duration = 5 * time.Second

func Run(ctx context.Context, args []string) error {
	cmdLine := &cmdLine{ctx: ctx}
	cmdParser, err := kong.New(cmdLine, cmdLineVars)
	if err != nil {
		return err
	}
	cmd, err := cmdParser.Parse(args)
	if err != nil {
		return err
	}
	err = cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func Start(ctx context.Context, path string) (*Server, error) {
	config, err := LoadConfig(path, false)
	if err != nil {
		return nil, err
	}
	return startConfig(ctx, config)
}

func MustStart(ctx context.Context, path string) *Server {
	s, err := Start(ctx, path)
	if err != nil {
		panic(err)
	}
	return s
}

func startConfig(ctx context.Context, config *Config) (*Server, error) {
	s := &Server{}
	err := s.initAndStart(config)
	if err != nil {
		return nil, err
	}
	s.stoppedWG.Add(1)
	go func() {
		defer s.stoppedWG.Done()
		s.run(ctx)
	}()
	return s, nil
}

const sessionCookiePath = "/session"

type Server struct {
	httpServer      *httpserver.Instance
	sessionCookie   *server.CookieHandler
	database        database.Driver
	userStore       userstore.Backend
	oauth2IssuerURL string
	oauth2Provider  *server.OAuth2Provider
	oauth2Client    *server.OAuth2Client
	authFLow        *oauth2client.AuthorizationCodeFlow[*oidc.IDTokenClaims]
	stoppedWG       sync.WaitGroup
}

func (s *Server) Issuer() string {
	return s.oauth2IssuerURL
}

func (s *Server) AddClient(client *OAuth2Client) error {
	return s.oauth2Provider.AddClient(client.oauth2Client())
}

func (s *Server) Shutdown(ctx context.Context) {
	err := s.shutdown(ctx)
	if err != nil {
		slog.Warn("shutdown failed; exiting", slog.Any("err", err))
	}
}

func (s *Server) WaitStopped() {
	s.stoppedWG.Wait()
}

func (s *Server) run(ctx context.Context) {
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	sigintCtx, cancelListenAndServe := context.WithCancel(ctx)
	go func() {
		<-sigint
		slog.Info("signal SIGINT; stopping")
		cancelListenAndServe()
	}()
	slog.Info("startup complete; running")
	<-sigintCtx.Done()
	s.shutdown(ctx)
}

func (s *Server) shutdown(ctx context.Context) error {
	slog.Info("initiating shutdown")
	shutdownCtx, cancelShutdown := context.WithTimeout(ctx, shutdownTimeout)
	defer cancelShutdown()
	err := errors.Join(s.httpServer.Shutdown(shutdownCtx), s.oauth2Provider.Close(), s.database.Close())
	if err != nil {
		return err
	}
	slog.Info("shutdown complete; exiting")
	return nil
}

func (s *Server) initAndStart(config *Config) error {
	inits := []func(*Config) error{
		s.initHttpServer,
		s.initDatabase,
		s.initUserStore,
		s.initProvider,
		s.initAuthFlow,
		s.startServer,
	}
	for _, init := range inits {
		err := init(config)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) initHttpServer(config *Config) error {
	httpServer := &httpserver.Instance{
		Addr:      config.Server.Address,
		AccessLog: config.Server.AccessLog,
	}
	err := httpServer.Listen()
	if err != nil {
		return err
	}
	// TODO: Warn in case of insecure setup
	secureCookies := config.Server.Protocol != ServerProtocolHttp
	sessionCookie := server.NewCookieHandler(config.Server.SessionCookie, sessionCookiePath, secureCookies, http.SameSiteLaxMode, int(config.Server.SessionCookieMaxAge.Seconds()))
	s.httpServer = httpServer
	s.sessionCookie = sessionCookie
	config.Server.Address = httpServer.ListenerAddr()
	s.oauth2IssuerURL = config.OAuth2IssuerURL()
	return nil
}

func (s *Server) initDatabase(config *Config) error {
	logger := slog.With(slog.String("driver", string(config.Database.Type)))
	logger.Info("initializing database")
	var driver database.Driver
	var err error
	switch config.Database.Type {
	case DatabaseTypeMemory:
		driver, err = database.OpenMemoryDB(logger)
	case DatabaseTypeSqlite:
		driver, err = database.OpenSQLite3DB(config.Database.SQLite.File, logger)
	case DatabaseTypePostgres:
		driver, err = database.OpenPostgresDB(fmt.Sprintf("postgres://%s:%s@%s/%s", config.Database.Postgres.User, config.Database.Postgres.Password, config.Database.Postgres.Address, config.Database.Postgres.DB), logger)
	default:
		err = fmt.Errorf("unrecognized database type: '%s'", config.Database.Type)
	}
	if err != nil {
		return err
	}
	logger.Info("updating database schema")
	fromSchema, toSchema, err := driver.UpdateSchema(context.Background())
	if err != nil {
		return err
	}
	if fromSchema != toSchema {
		logger.Info("database schema updated", slog.String("from", string(fromSchema)), slog.String("to", string(toSchema)))
	} else {
		logger.Info("database schema already up-to-date")
	}
	s.database = driver
	return nil
}

func (s *Server) initUserStore(config *Config) error {
	logger := slog.With(slog.String("store", string(config.UserStore.Type)))
	logger.Info("initializing user store")
	var backend userstore.Backend
	var err error
	switch config.UserStore.Type {
	case UserStoreTypeLDAP:
		ldapConfig, err2 := config.ldapUserstoreConfig()
		err = err2
		if err == nil {
			backend, err = userstore.NewLDAPBackend(ldapConfig, logger)
		}
	case UserStoreTypeStatic:
		backend, err = userstore.NewStaticBackend(config.staticUsers(), logger)
	default:
		err = fmt.Errorf("unrecognized user store type: '%s'", config.UserStore.Type)
	}
	if err != nil {
		return err
	}
	s.userStore = backend
	return nil
}

func (s *Server) initProvider(config *Config) error {
	logger := slog.With(slog.String("issuer", s.oauth2IssuerURL))
	opOpts := make([]op.Option, 0, 2)
	opOpts = append(opOpts, op.WithLogger(logger))
	if config.Server.Protocol == ServerProtocolHttp {
		opOpts = append(opOpts, op.WithAllowInsecure())
	}
	logger.Info("initializing OAuth2 provider")
	providerConfig := config.oauth2ProviderConfig()
	provider, err := providerConfig.NewProvider(s.database, s.userStore, opOpts...)
	if err != nil {
		return err
	}
	for _, client := range config.oauth2Clients() {
		err = provider.AddClient(client)
		if err != nil {
			return err
		}
	}
	oauth2Client := &server.OAuth2Client{
		ID:           uuid.NewString(),
		Secret:       uuid.NewString(),
		RedirectURLs: []string{providerConfig.Issuer + "/authorized"},
	}
	err = provider.AddClient(oauth2Client)
	if err != nil {
		return err
	}
	s.oauth2Provider = provider
	s.oauth2Client = oauth2Client
	return nil
}

func (s *Server) initAuthFlow(config *Config) error {
	authFlowConfig := &oauth2client.AuthorizationCodeFlowConfig[*oidc.IDTokenClaims]{
		BaseURL:      s.oauth2IssuerURL,
		Issuer:       s.oauth2IssuerURL,
		ClientId:     s.oauth2Client.ID,
		ClientSecret: s.oauth2Client.Secret,
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess, "groups"},
		EnablePKCE:   true,
	}
	authFlow, err := authFlowConfig.NewFlow(&http.Client{}, context.Background(), s.tokenExchange)
	if err != nil {
		return err
	}
	s.authFLow = authFlow
	return nil
}

func (s *Server) startServer(config *Config) error {
	s.oauth2Provider.Mount(s.httpServer)
	s.authFLow.Mount(s.httpServer)
	if !config.Mock.Enabled {
		web.Mount(s.httpServer)
	} else {
		s.httpServer.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
			s.handleUserMock(w, r, config.Mock.Email, config.Mock.Password, config.Mock.Rembemer)
		})
	}
	s.httpServer.HandleFunc("/session", s.handleSession)
	s.httpServer.HandleFunc("/session/authenticate", s.handleSessionAuthenticate)
	s.httpServer.HandleFunc("/session/verify", s.handleSessionVerify)
	s.httpServer.HandleFunc("/session/terminate", s.handleSessionTerminate)
	switch config.Server.Protocol {
	case ServerProtocolHttp:
		return s.httpServer.Serve()
	case ServerProtocolHttps:
		return s.httpServer.ServeTLS(config.Server.CertFile, config.Server.KeyFile)
	default:
		return fmt.Errorf("unexpected server protocol: %s", config.Server.Protocol)
	}
}

func (s *Server) handleUserMock(w http.ResponseWriter, r *http.Request, email string, password string, remember bool) {
	id := r.URL.Query().Get("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	redirectURL, err := s.oauth2Provider.Authenticate(r.Context(), id, email, password, remember)
	if errors.Is(err, userstore.ErrInvalidLogin) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sessionId, exists := s.sessionCookie.Get(r)
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	// TODO: Handle persistent user session
	_, err := s.database.SelectUserSession(ctx, sessionId)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	httpClient, err := s.authFLow.Client(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	userInfoResponse, err := httpClient.Get(s.authFLow.UserinfoEndpoint())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if userInfoResponse.StatusCode != http.StatusOK {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	io.Copy(w, userInfoResponse.Body)
}

func (s *Server) handleSessionAuthenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		slog.Error("invalid authenticate session request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err := r.ParseForm()
	if err != nil {
		slog.Error("failed to parse authenticate session request", slog.Any("err", err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id := r.PostFormValue("id")
	email := r.PostFormValue("email")
	verification := r.PostFormValue("verification")
	password := r.PostFormValue("password")
	if id == "" || email == "" || password == "" || verification == "" {
		slog.Error("incomplete authenticate session request", slog.String("id", id), slog.String("email", email), slog.String("verification", verification))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	remember, _ := strconv.ParseBool(r.PostFormValue("remember"))
	redirectURL, err := s.oauth2Provider.Authenticate(r.Context(), id, email, password, remember)
	if errors.Is(err, userstore.ErrInvalidLogin) {
		slog.Warn("authenticate session failure", slog.String("id", id), slog.String("email", email))
		w.WriteHeader(http.StatusUnauthorized)
		return
	} else if err != nil {
		slog.Warn("authenticate session error", slog.String("id", id), slog.String("email", email), slog.Any("err", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleSessionVerify(w http.ResponseWriter, r *http.Request) {

}

func (s *Server) handleSessionTerminate(w http.ResponseWriter, r *http.Request) {
	s.sessionCookie.Delete(w)
}

func (s *Server) tokenExchange(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, flow *oauth2client.AuthorizationCodeFlow[*oidc.IDTokenClaims]) {
	ctx := r.Context()
	userSession, err := s.database.TransformAndDeleteUserSessionRequest(ctx, state, tokens.Token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.sessionCookie.Set(w, userSession.ID, userSession.Remember)
	http.Redirect(w, r, s.oauth2IssuerURL, http.StatusFound)
}
