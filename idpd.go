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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
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
	"github.com/tdrn-org/idpd/internal/server/mail"
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
	mailer          *mail.Mailer
	database        database.Driver
	userStore       userstore.Backend
	oauth2IssuerURL *url.URL
	oauth2Provider  *server.OAuth2Provider
	oauth2Client    *server.OAuth2Client
	authFLow        *oauth2client.AuthorizationCodeFlow[*oidc.IDTokenClaims]
	stoppedWG       sync.WaitGroup
}

func (s *Server) OAuth2IssuerURL() *url.URL {
	return s.oauth2IssuerURL
}

func (s *Server) AddOAuth2Client(client *OAuth2Client) error {
	return s.oauth2Provider.AddClient(&server.OAuth2Client{
		ID:           client.ID,
		Secret:       client.Secret,
		RedirectURLs: client.RedirectURLs,
	})
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
		s.initMailer,
		s.initDatabase,
		s.initUserStore,
		s.initOAuth2Provider,
		s.initOAuth2AuthFlow,
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
	issuerURL, err := config.oauth2IssuerURL(httpServer)
	if err != nil {
		return err
	}
	// TODO: Warn in case of insecure setup
	secureCookies := config.Server.Protocol != ServerProtocolHttp
	sessionCookie := server.NewCookieHandler(config.Server.SessionCookie, sessionCookiePath, secureCookies, http.SameSiteLaxMode, int(config.Server.SessionCookieMaxAge.Seconds()))
	s.httpServer = httpServer
	s.sessionCookie = sessionCookie
	s.oauth2IssuerURL = issuerURL
	return nil
}

func (s *Server) initMailer(config *Config) error {
	mailer, err := config.toMailConfig().NewMailer()
	if err != nil {
		return err
	}
	s.mailer = mailer
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
		ldapConfig, err2 := config.toLDAPUserstoreConfig()
		err = err2
		if err == nil {
			backend, err = userstore.NewLDAPBackend(ldapConfig, logger)
		}
	case UserStoreTypeStatic:
		backend, err = userstore.NewStaticBackend(config.toStaticUsers(), logger)
	default:
		err = fmt.Errorf("unrecognized user store type: '%s'", config.UserStore.Type)
	}
	if err != nil {
		return err
	}
	s.userStore = backend
	return nil
}

func (s *Server) initOAuth2Provider(config *Config) error {
	logger := slog.With(slog.String("issuer", s.oauth2IssuerURL.String()))
	opOpts := make([]op.Option, 0, 2)
	opOpts = append(opOpts, op.WithLogger(logger))
	if config.Server.Protocol == ServerProtocolHttp {
		opOpts = append(opOpts, op.WithAllowInsecure())
	}
	logger.Info("initializing OAuth2 provider")
	providerConfig, err := config.toOAuth2ProviderConfig(s.httpServer)
	if err != nil {
		return err
	}
	provider, err := providerConfig.NewProvider(s.database, s.userStore, opOpts...)
	if err != nil {
		return err
	}
	for _, client := range config.OAuth2.Clients {
		err = provider.AddClient(client.toServerOAuth2Client())
		if err != nil {
			return err
		}
	}
	oauth2Client := &server.OAuth2Client{
		ID:           uuid.NewString(),
		Secret:       uuid.NewString(),
		RedirectURLs: []string{providerConfig.IssuerURL.JoinPath("/authorized").String()},
	}
	err = provider.AddClient(oauth2Client)
	if err != nil {
		return err
	}
	s.oauth2Provider = provider
	s.oauth2Client = oauth2Client
	return nil
}

func (s *Server) initOAuth2AuthFlow(config *Config) error {
	authFlowConfig := &oauth2client.AuthorizationCodeFlowConfig[*oidc.IDTokenClaims]{
		BaseURL:      s.oauth2IssuerURL.String(),
		Issuer:       s.oauth2IssuerURL.String(),
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
			s.handleUserMock(w, r, config.Mock.Subject, config.Mock.Password, config.Mock.Rembemer)
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

func (s *Server) handleUserMock(w http.ResponseWriter, r *http.Request, subject string, password string, remember bool) {
	id := r.URL.Query().Get("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	verifyHandler := server.MockVerifyHandler()
	_, err := s.oauth2Provider.Authenticate(r.Context(), id, subject, password, verifyHandler, remember)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	redirectURL, err := s.oauth2Provider.Verify(r.Context(), id, subject, verifyHandler, "")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

type UserInfo struct {
	Name             string    `json:"name"`
	Subject          string    `json:"subject"`
	Email            string    `json:"email"`
	TOTPRegistration time.Time `json:"totp_registration,omitzero"`
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	client, err := s.authFlowClient(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	oidcUserInfo, err := s.authFLow.GetUserInfo(client, r.Context())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	name := oidcUserInfo.Name
	if name == "" {
		name = oidcUserInfo.Subject
	}
	userInfo := &UserInfo{
		Name:    name,
		Subject: oidcUserInfo.Subject,
		Email:   oidcUserInfo.Email,
	}
	err = json.NewEncoder(w).Encode(userInfo)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleSessionAuthenticate(w http.ResponseWriter, r *http.Request) {
	id, subject, password, verification, remember, err := s.parseAuthenticateForm(r)
	if err != nil {
		slog.Error("failed to process authenticate session request", slog.Any("err", err))
		s.redirectAlert(w, r, AlertLoginFailure)
		return
	}
	verifyHandler := s.getVerifyHandler(verification)
	redirectURL, err := s.oauth2Provider.Authenticate(r.Context(), id, subject, password, verifyHandler, remember)
	if err != nil {
		slog.Warn("authenticate session error", slog.String("id", id), slog.String("subject", subject), slog.Any("err", err))
		s.redirectAlert(w, r, AlertLoginFailure)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) getVerifyHandler(verification string) server.VerifyHandler {
	switch server.VerifyMethod(verification) {
	case server.VerifyMethodEmail:
		return server.EmailVerifyHandler(s.mailer, s.userStore)
	case server.VerifyMethodTOTP:
		return server.NoneVerifyHandler()
	case server.VerifyMethodPasskey:
		return server.NoneVerifyHandler()
	case server.VerifyMethodWebAuthn:
		return server.NoneVerifyHandler()
	default:
		return server.NoneVerifyHandler()
	}
}

func (s *Server) parseAuthenticateForm(r *http.Request) (string, string, string, string, bool, error) {
	if r.Method != http.MethodPost {
		return "", "", "", "", false, fmt.Errorf("invalid authenticate session request")
	}
	err := r.ParseForm()
	if err != nil {
		return "", "", "", "", false, fmt.Errorf("failed to parse authenticate session request")
	}
	id := r.PostFormValue("id")
	subject := r.PostFormValue("subject")
	password := r.PostFormValue("password")
	verification := r.PostFormValue("verification")
	if id == "" || subject == "" || password == "" || verification == "" {
		return "", "", "", "", false, fmt.Errorf("incomplete authenticate session request (id='%s', subject='%s', verification='%s')", id, subject, verification)
	}
	remember, _ := strconv.ParseBool(r.PostFormValue("remember"))
	return id, subject, password, verification, remember, nil
}

func (s *Server) handleSessionVerify(w http.ResponseWriter, r *http.Request) {
	id, subject, verification, response, err := s.parseVerifyForm(r)
	if err != nil {
		slog.Error("failed to process verify session request", slog.Any("err", err))
		s.redirectAlert(w, r, AlertLoginFailure)
		return
	}
	verifyHandler := s.getVerifyHandler(verification)
	redirectURL, err := s.oauth2Provider.Verify(r.Context(), id, subject, verifyHandler, response)
	if err != nil {
		slog.Warn("verify session failure", slog.String("id", id), slog.String("subject", subject), slog.Any("err", err))
		s.redirectAlert(w, r, AlertLoginFailure)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) parseVerifyForm(r *http.Request) (string, string, string, string, error) {
	if r.Method != http.MethodPost {
		return "", "", "", "", fmt.Errorf("invalid verify session request")
	}
	err := r.ParseForm()
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse verify session request")
	}
	id := r.PostFormValue("id")
	subject := r.PostFormValue("subject")
	verification := r.PostFormValue("verification")
	response := r.PostFormValue("response")
	if id == "" || subject == "" || verification == "" || response == "" {
		return "", "", "", "", fmt.Errorf("incomplete verify session request (id='%s', subject='%s', verification='%s')", id, subject, verification)
	}
	return id, subject, verification, response, nil
}

func (s *Server) handleSessionTerminate(w http.ResponseWriter, r *http.Request) {
	client, err := s.authFlowClient(r)
	alert := AlertNone
	if err == nil {
		endSessionResponse, err := client.Get(s.authFLow.GetEndSessionEndpoint())
		if err != nil || endSessionResponse.StatusCode != http.StatusOK {
			alert = AlertLogoffFailure
		}
	}
	s.sessionCookie.Delete(w)
	if alert != AlertNone {
		s.redirectAlert(w, r, alert)
	}
	http.Redirect(w, r, s.oauth2IssuerURL.String(), http.StatusFound)
}

func (s *Server) tokenExchange(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, flow *oauth2client.AuthorizationCodeFlow[*oidc.IDTokenClaims]) {
	ctx := r.Context()
	userSession, err := s.database.TransformAndDeleteUserSessionRequest(ctx, state, tokens.Token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.sessionCookie.Set(w, userSession.ID, userSession.Remember)
	http.Redirect(w, r, s.oauth2IssuerURL.String(), http.StatusFound)
}

func (s *Server) sessionID(r *http.Request) (string, error) {
	sessionID, exists := s.sessionCookie.Get(r)
	if !exists {
		return "", oauth2client.ErrNotAuthenticated
	}
	return sessionID, nil
}

func (s *Server) authFlowClient(r *http.Request) (*http.Client, error) {
	sessionID, err := s.sessionID(r)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	session, err := s.database.SelectUserSession(ctx, sessionID)
	if err != nil {
		return nil, oauth2client.ErrNotAuthenticated
	}
	client, err := s.authFLow.Client(ctx, session.OAuth2Token())
	if err != nil {
		return nil, err
	}
	return client, nil
}

type Alert string

const (
	AlertNone          Alert = ""
	AlertLoginFailure  Alert = "login_failure"
	AlertLogoffFailure Alert = "logoff_failure"
)

func (s *Server) redirectAlert(w http.ResponseWriter, r *http.Request, alert Alert) {
	redirectURL := *s.oauth2IssuerURL
	query := redirectURL.Query()
	query.Add("alert", string(alert))
	redirectURL.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
