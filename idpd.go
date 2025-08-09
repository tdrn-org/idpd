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
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/alecthomas/kong"
	"github.com/google/uuid"
	"github.com/tdrn-org/idpd/httpserver"
	"github.com/tdrn-org/idpd/internal/server"
	serverconf "github.com/tdrn-org/idpd/internal/server/conf"
	"github.com/tdrn-org/idpd/internal/server/database"
	"github.com/tdrn-org/idpd/internal/server/geoip"
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
	httpServer       *httpserver.Instance
	sessionCookie    *server.CookieHandler
	mailer           *mail.Mailer
	totpProvider     *server.TOTPProvider
	locationService  *geoip.LocationService
	database         database.Driver
	userStore        userstore.Backend
	oauth2IssuerURL  *url.URL
	oauth2Provider   *server.OAuth2Provider
	oauth2Client     *server.OAuth2Client
	authFLow         *oauth2client.AuthorizationCodeFlow[*oidc.IDTokenClaims]
	jobTicker        *time.Ticker
	jobTickerStopped chan bool
	stoppedWG        sync.WaitGroup
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
	// Stop background job processing
	s.jobTicker.Stop()
	s.jobTickerStopped <- true
	// Stop/Close running services
	err := errors.Join(s.httpServer.Shutdown(shutdownCtx), s.oauth2Provider.Close(), s.database.Close(), s.locationService.Close())
	if err != nil {
		return err
	}
	slog.Info("shutdown complete; exiting")
	return nil
}

func (s *Server) initAndStart(config *Config) error {
	inits := []func(*Config) error{
		s.initServerConf,
		s.initHttpServer,
		s.initMailer,
		s.initTOTP,
		s.initGeoIP,
		s.initDatabase,
		s.initUserStore,
		s.initOAuth2Provider,
		s.initOAuth2AuthFlow,
		s.startJobTicker,
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

func (s *Server) initServerConf(config *Config) error {
	runtime := &serverconf.Runtime{
		SessionLifetime: config.Server.SessionLifetime.Duration,
		RequestLifetime: config.Server.RequestLifetime.Duration,
		TokenLifetime:   config.Server.TokenLifetime.Duration,
	}
	runtime.Bind()
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
	secureCookies := ServerProtocol(issuerURL.Scheme) != ServerProtocolHttp
	if !secureCookies {
		slog.Warn("unsecure server protocol; disabling secure cookies")
	}
	sessionCookie := server.NewCookieHandler(config.Server.SessionCookie, sessionCookiePath, secureCookies, http.SameSiteLaxMode)
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

func (s *Server) initTOTP(config *Config) error {
	s.totpProvider = config.toTOTPConfig(s.oauth2IssuerURL.Host).NewTOTPProvider()
	return nil
}

func (s *Server) initGeoIP(config *Config) error {
	_, err := os.Stat(config.GeoIP.CityDB)
	if err != nil {
		s.locationService = geoip.NewLocationService(geoip.DummyProvider(), nil)
		return nil
	}
	slog.Info("intializing GeoIP provider", slog.String("db", config.GeoIP.CityDB))
	provider, err := geoip.OpenMaxMindDB(config.GeoIP.CityDB)
	if err != nil {
		return err
	}
	s.locationService = geoip.NewLocationService(provider, nil)
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
	issuerURL := s.oauth2IssuerURL
	logger := slog.With(slog.String("issuer", issuerURL.String()))
	opOpts := make([]op.Option, 0, 2)
	opOpts = append(opOpts, op.WithLogger(logger))
	if ServerProtocol(issuerURL.Scheme) == ServerProtocolHttp {
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

func (s *Server) startJobTicker(config *Config) error {
	schedule := 5 * time.Minute
	s.jobTicker = time.NewTicker(schedule)
	s.jobTickerStopped = make(chan bool)
	slog.Info("starting job ticker", slog.String("schedule", schedule.String()))
	s.stoppedWG.Add(1)
	go func() {
		defer s.stoppedWG.Done()
		for stopped := false; !stopped; {
			select {
			case <-s.jobTickerStopped:
				stopped = true
			case <-s.jobTicker.C:
				s.runJobs()
			}
		}
		slog.Info("job ticker stopped")
	}()
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
	s.httpServer.HandleFunc("/session/details", s.handleSessionDetails)
	s.httpServer.HandleFunc("/session/authenticate", s.handleSessionAuthenticate)
	s.httpServer.HandleFunc("/session/verify", s.handleSessionVerify)
	s.httpServer.HandleFunc("/session/terminate", s.handleSessionTerminate)
	s.httpServer.HandleFunc("/session/totp_register", s.handleSessionTOTPRegister)
	s.httpServer.HandleFunc("/session/totp_verify", s.handleSessionTOTPVerify)
	switch config.Server.Protocol {
	case ServerProtocolHttp:
		return s.httpServer.Serve()
	case ServerProtocolHttps:
		return s.httpServer.ServeTLS(config.Server.CertFile, config.Server.KeyFile)
	default:
		return fmt.Errorf("unexpected server protocol: %s", config.Server.Protocol)
	}
}
