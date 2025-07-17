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
	"crypto/rand"
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
	"github.com/tdrn-org/idpd/idpclient"
	"github.com/tdrn-org/idpd/internal/server"
	"github.com/tdrn-org/idpd/internal/server/database"
	"github.com/tdrn-org/idpd/internal/server/userstore"
	"github.com/tdrn-org/idpd/internal/server/web"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const shutdownTimeout time.Duration = 5 * time.Second

func Run(args []string) error {
	cmd := &cmdLine{}
	parser, err := kong.New(cmd, cmdLineVars)
	if err != nil {
		return err
	}
	ctx, err := parser.Parse(args)
	if err != nil {
		return err
	}
	err = ctx.Run()
	if err != nil {
		return err
	}
	return nil
}

func Start(path string) (*Server, error) {
	config, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	return startConfig(config)
}

func MustStart(path string) *Server {
	config, err := LoadConfig(path)
	if err != nil {
		panic(err)
	}
	s, err := startConfig(config)
	if err != nil {
		panic(err)
	}
	return s
}

func startConfig(config *Config) (*Server, error) {
	s := &Server{}
	err := s.initAndStart(config)
	if err != nil {
		return nil, err
	}
	s.stoppedWG.Add(1)
	go func() {
		defer s.stoppedWG.Done()
		s.run()
	}()
	return s, nil
}

type Server struct {
	httpServer    *httpserver.Instance
	cookieHandler *httphelper.CookieHandler
	sessionCookie string
	issuerURL     string
	database      database.Driver
	userStore     userstore.Backend
	provider      *server.OpenIDProvider
	authClient    *server.OpenIDClient
	authFLow      *idpclient.AuthorizationCodeFlow[*oidc.IDTokenClaims]
	stoppedWG     sync.WaitGroup
}

func (s *Server) Issuer() string {
	return s.issuerURL
}

func (s *Server) AddClient(client *Client) error {
	return s.provider.AddClient(client.openIDClient())
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

func (s *Server) run() {
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	sigintCtx, cancelListenAndServe := context.WithCancel(context.Background())
	go func() {
		<-sigint
		slog.Info("signal SIGINT; stopping")
		cancelListenAndServe()
	}()
	slog.Info("startup complete; running")
	<-sigintCtx.Done()
	s.shutdown(context.Background())
}

func (s *Server) shutdown(ctx context.Context) error {
	slog.Info("initiating shutdown")
	shutdownCtx, cancelShutdown := context.WithTimeout(ctx, shutdownTimeout)
	defer cancelShutdown()
	err := errors.Join(s.httpServer.Shutdown(shutdownCtx), s.provider.Close(), s.database.Close())
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
		Addr: config.Server.Address,
	}
	err := httpServer.Listen()
	if err != nil {
		return err
	}
	cookieHandler, err := newCookieHandler(config.OpenID.AllowInsecure)
	if err != nil {
		return err
	}
	s.httpServer = httpServer
	s.cookieHandler = cookieHandler
	s.sessionCookie = config.Server.SessionCookie
	config.Server.Address = httpServer.ListenerAddr()
	s.issuerURL = config.OpenIDIssuerURL()
	return nil
}

func (s *Server) initDatabase(config *Config) error {
	logger := slog.With(slog.String("driver", config.Database.Type))
	logger.Info("initializing database")
	var driver database.Driver
	var err error
	switch config.Database.Type {
	case "memory":
		driver, err = database.OpenMemoryDB(logger)
	case "sqlite":
		driver, err = database.OpenSQLite3DB(config.Database.SQLite.File, logger)
	case "postgres":
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
	logger := slog.With(slog.String("store", config.UserStore.Type))
	logger.Info("initializing user store")
	var backend userstore.Backend
	var err error
	switch config.UserStore.Type {
	case "ldap":
		ldapConfig, err2 := config.ldapUserstoreConfig()
		err = err2
		if err == nil {
			backend, err = userstore.NewLDAPBackend(ldapConfig, logger)
		}
	case "static":
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
	logger := slog.With(slog.String("issuer", s.issuerURL))
	opOpts := make([]op.Option, 0, 2)
	opOpts = append(opOpts, op.WithLogger(logger))
	if config.OpenID.AllowInsecure {
		opOpts = append(opOpts, op.WithAllowInsecure())
	}
	logger.Info("initializing OpenID provider")
	providerConfig := config.openIDProviderConfig()
	provider, err := providerConfig.NewProvider(s.database, s.userStore, opOpts...)
	if err != nil {
		return err
	}
	for _, client := range config.openIDClients() {
		err = provider.AddClient(client)
		if err != nil {
			return err
		}
	}
	authClient := &server.OpenIDClient{
		ID:           uuid.NewString(),
		Secret:       uuid.NewString(),
		RedirectURLs: []string{providerConfig.Issuer + "/authorized"},
	}
	err = provider.AddClient(authClient)
	if err != nil {
		return err
	}
	s.provider = provider
	s.authClient = authClient
	return nil
}

func (s *Server) initAuthFlow(config *Config) error {
	authFlowConfig := &idpclient.AuthorizationCodeFlowConfig[*oidc.IDTokenClaims]{
		BaseURL:         s.issuerURL,
		AuthURLPath:     "/login",
		RedirectURLPath: "/authorized",
		Issuer:          s.issuerURL,
		ClientId:        s.authClient.ID,
		ClientSecret:    s.authClient.Secret,
		Scopes:          []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess, "groups"},
		EnablePKCE:      true,
	}
	authFlow, err := authFlowConfig.NewFlow(&http.Client{}, context.Background(), s.tokenExchange)
	if err != nil {
		return err
	}
	s.authFLow = authFlow
	return nil
}

func (s *Server) startServer(config *Config) error {
	s.provider.Mount(s.httpServer)
	s.authFLow.Mount(s.httpServer)
	if !config.Mock.Enabled {
		web.Mount(s.httpServer)
	} else {
		s.httpServer.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
			s.handleUserMock(w, r, config.Mock.Email, config.Mock.Password, config.Mock.Rembemer)
		})
	}
	s.httpServer.HandleFunc("/session", s.handleSession)
	s.httpServer.HandleFunc("/session/login", s.handleSessionLogin)
	s.httpServer.HandleFunc("/session/logoff", s.handleSessionLogoff)
	switch config.Server.Protocol {
	case "http":
		return s.httpServer.Serve()
	case "https":
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
	redirectURL, err := s.provider.Authenticate(r.Context(), id, email, password, remember)
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
	sessionId, err := s.cookieHandler.CheckCookie(r, s.sessionCookie)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	userSession, err := s.database.SelectUserSession(ctx, sessionId)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	httpClient, err := s.authFLow.Client(ctx, userSession.OAuth2Token())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	userinfoEndpoint, err := s.authFLow.UserinfoEndpoint()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	userInfoResponse, err := httpClient.Get(userinfoEndpoint)
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

func (s *Server) handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err := r.ParseForm()
	if err != nil {
		slog.Error("failed to parse login request", slog.Any("err", err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id := r.PostFormValue("id")
	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	if id == "" || email == "" || password == "" {
		slog.Error("incomplete login request", slog.String("id", id), slog.String("email", email))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	remember, _ := strconv.ParseBool(r.PostFormValue("remember"))
	redirectURL, err := s.provider.Authenticate(r.Context(), id, email, password, remember)
	if errors.Is(err, userstore.ErrInvalidLogin) {
		slog.Warn("login failure", slog.String("id", id), slog.String("email", email))
		w.WriteHeader(http.StatusUnauthorized)
		return
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleSessionLogoff(w http.ResponseWriter, r *http.Request) {
	s.cookieHandler.DeleteCookie(w, s.sessionCookie)
}

func (s *Server) tokenExchange(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
	ctx := r.Context()
	userSession, err := s.database.TransformAndDeleteUserSessionRequest(ctx, state, tokens.Token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.cookieHandler.SetCookie(w, s.sessionCookie, userSession.ID)
	http.Redirect(w, r, s.issuerURL, http.StatusFound)
}

func newCookieHandler(unsecure bool) (*httphelper.CookieHandler, error) {
	hashKey := make([]byte, 64)
	_, err := rand.Read(hashKey)
	if err != nil {
		return nil, fmt.Errorf("failed read random bytes (cause: %w)", err)
	}
	encryptKey := make([]byte, 32)
	_, err = rand.Read(encryptKey)
	if err != nil {
		return nil, fmt.Errorf("failed read random bytes (cause: %w)", err)
	}
	opts := make([]httphelper.CookieHandlerOpt, 0, 1)
	if unsecure {
		opts = append(opts, httphelper.WithUnsecure())
	}
	return httphelper.NewCookieHandler(hashKey, encryptKey, opts...), nil
}
