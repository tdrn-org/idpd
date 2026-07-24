/*
 * Copyright 2025-2026 Holger de Carne
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
	"sync"
	"time"

	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/go-database/memory"
	"github.com/tdrn-org/go-database/postgres"
	"github.com/tdrn-org/go-database/sqlite"
	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/config"
	"github.com/tdrn-org/idpd/internal/adapters/middleware/rest"
	"github.com/tdrn-org/idpd/internal/data"
	"github.com/tdrn-org/idpd/internal/data/model"
	"github.com/tdrn-org/idpd/internal/scheme"
	"github.com/tdrn-org/idpd/internal/scheme/forward"
	"github.com/tdrn-org/idpd/internal/scheme/oauth2"
	"github.com/tdrn-org/idpd/internal/scheme/saml2"
	"github.com/tdrn-org/idpd/internal/userstore"
	"github.com/tdrn-org/idpd/internal/userstore/demo"
	"github.com/tdrn-org/idpd/internal/userstore/ldap"
	"github.com/tdrn-org/idpd/internal/userstore/tomlfile"
)

const serverJobTickerSchedule time.Duration = 5 * time.Minute

type Server struct {
	cfg                 *config.Config
	dataStore           *data.Store
	users               userstore.Backend
	httpServer          *httpserver.Instance
	baseURL             *url.URL
	schemeHandlers      map[scheme.Name]scheme.Handler
	jobTicker           *time.Ticker
	jobTickerShutdown   chan any
	jobTickerShutdownWG sync.WaitGroup
	jobs                []jobFunc
	logger              *slog.Logger
}

func StartServer(ctx context.Context, cfg *config.Config) (*Server, error) {
	applyLoggingConfig(&cfg.Logging)
	// Setup early logger with configuration address (which may not be the final one).
	// We will reset the logger after listener has been created.
	earlyLogger := slog.With(slog.String("server", cfg.Server.Address))
	s := &Server{
		cfg:            cfg,
		schemeHandlers: make(map[scheme.Name]scheme.Handler),
		logger:         earlyLogger,
	}
	startFuncs := []func(context.Context, *config.Config) error{
		s.startStore,
		s.startUserstore,
		s.startHttpServer,
		s.startRestAPI,
		s.startSchemeHandlers,
		s.startJobTicker,
	}
	for _, startFunc := range startFuncs {
		err := startFunc(ctx, cfg)
		if err != nil {
			defer s.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Server) Run(ctx context.Context) error {
	s.logger.Info("serving HTTP requests...")
	err := s.httpServer.Serve()
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	shutdownFuncs := []func(context.Context) error{
		s.shutdownJobTicker,
		s.shutdownHttpServer,
	}
	shutdownErrs := make([]error, 0, len(shutdownFuncs))
	for _, shutdownFunc := range shutdownFuncs {
		shutdownErrs = append(shutdownErrs, shutdownFunc(ctx))
	}
	return errors.Join(shutdownErrs...)
}

func (s *Server) Close() error {
	closeFuncs := []func() error{
		s.closeHttpServer,
		s.closeUserstore,
		s.closeStore,
	}
	closeErrs := make([]error, 0, len(closeFuncs))
	for _, closeFunc := range closeFuncs {
		closeErrs = append(closeErrs, closeFunc())
	}
	return errors.Join(closeErrs...)
}

func (s *Server) startStore(ctx context.Context, cfg *config.Config) error {
	s.logger.Info("starting data store...", slog.String("type", string(cfg.Store.DatabaseType)))
	var databaseConfig database.Config
	var err error
	switch cfg.Store.DatabaseType {
	case config.DatabaseType(memory.Type):
		databaseConfig = memory.NewConfig(model.SqliteSchemaScriptOption)
	case config.DatabaseType(sqlite.Type):
		databaseConfig = sqlite.NewConfig(cfg.Store.SQLiteConfig.File, sqlite.ModeRWC, model.SqliteSchemaScriptOption)
	case config.DatabaseType(postgres.Type):
		databaseConfig, err = postgres.NewConfig(cfg.Store.PostgresConfig.DB, cfg.Store.PostgresConfig.User, cfg.Store.PostgresConfig.Password, postgres.WithAddress(cfg.Store.PostgresConfig.Address), model.PostgresSchemaScriptOption)
	default:
		err = fmt.Errorf("unrecognized store type '%s'", cfg.Store.DatabaseType)
	}
	if err != nil {
		return err
	}
	driver, err := database.Open(databaseConfig)
	if err != nil {
		return err
	}
	_, _, err = driver.UpdateSchema(ctx)
	if err != nil {
		return errors.Join(err, driver.Close())
	}
	s.dataStore = data.NewStore(driver, databaseConfig.RedactedDSN(), &cfg.General)
	return nil
}

func (s *Server) closeStore() error {
	if s.dataStore == nil {
		return nil
	}
	s.logger.Info("closing data store")
	return s.dataStore.Close()
}

func (s *Server) startUserstore(ctx context.Context, cfg *config.Config) error {
	s.logger.Info("starting userstore...", slog.String("type", string(cfg.Userstore.Type)))
	var users userstore.Backend
	var err error
	switch cfg.Userstore.Type {
	case config.UserstoreType(ldap.Type):
		users, err = userstore.Open(ldapUserstoreConfig(&cfg.Userstore))
	case config.UserstoreType(tomlfile.Type):
		users, err = userstore.Open(fileUserstoreConfig(&cfg.Userstore))
	case config.UserstoreType(demo.Type):
		users, err = userstore.Open(demoUserstoreConfig(&cfg.Userstore))
	default:
		err = fmt.Errorf("unrecognized userstore type '%s'", cfg.Userstore.Type)
	}
	if err != nil {
		return err
	}
	s.users = users
	return nil
}

func (s *Server) closeUserstore() error {
	if s.users == nil {
		return nil
	}
	return s.users.Close()
}

func (s *Server) startHttpServer(ctx context.Context, cfg *config.Config) error {
	s.logger.Info("starting HTTP server...", slog.String("address", cfg.Server.Address))
	httpServerOptions := httpServerOptions(&cfg.Server)
	httpServer, err := httpserver.Listen(ctx, "tcp", cfg.Server.Address, httpServerOptions...)
	if err != nil {
		return err
	}
	s.httpServer = httpServer
	if cfg.Server.PublicURL.URL != nil {
		s.baseURL = cfg.Server.PublicURL.URL
	} else {
		s.baseURL = httpServer.BaseURL()
	}
	// Replace early logger by one attributed with actual URL
	s.logger = slog.With(slog.String("baseURL", s.baseURL.String()))
	return nil
}

func (s *Server) shutdownHttpServer(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	s.logger.Info("shutting down HTTP server...")
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) closeHttpServer() error {
	if s.httpServer == nil {
		return nil
	}
	s.logger.Info("closing HTTP server...")
	return s.httpServer.Close()
}

func (s *Server) startRestAPI(_ context.Context, _ *config.Config) error {
	rest.NewAPI(s.runtime()).Mount(s.httpServer)
	return nil
}

func (s *Server) startSchemeHandlers(_ context.Context, cfg *config.Config) error {
	if cfg.OAuth2.Enabled {
		s.logger.Info("enabling OAuth2 scheme")
		handler, err := oauth2.NewHandler(s.runtime(), &cfg.OAuth2)
		if err != nil {
			return err
		}
		handler.Mount(s.httpServer)
		s.schemeHandlers[handler.Name()] = handler
	}
	if cfg.SAML2.Enabled {
		s.logger.Info("enabling SAML2 scheme")
		handler, err := saml2.NewHandler(s.runtime(), &cfg.SAML2)
		if err != nil {
			return err
		}
		handler.Mount(s.httpServer)
		s.schemeHandlers[handler.Name()] = handler
	}
	if cfg.Forward.Enabled {
		s.logger.Info("enabling Forward scheme")
		handler := forward.NewHandler(s.runtime())
		handler.Mount(s.httpServer)
		s.schemeHandlers[handler.Name()] = handler
	}
	return nil
}

func (s *Server) startJobTicker(_ context.Context, cfg *config.Config) error {
	schedule := serverJobTickerSchedule
	s.logger.Info("starting job ticker...", slog.String("schedule", schedule.String()))
	s.jobs = []jobFunc{}
	s.jobTicker = time.NewTicker(schedule)
	s.jobTickerShutdown = make(chan any)
	s.jobTickerShutdownWG.Go(func() {
		for stopped := false; !stopped; {
			select {
			case <-s.jobTickerShutdown:
				stopped = true
			case <-s.jobTicker.C:
				s.runJobs()
			}
		}
		s.logger.Info("job ticker stopped")
	})
	return nil
}

func (s *Server) shutdownJobTicker(_ context.Context) error {
	s.logger.Info("shutting down job ticker...")
	s.jobTicker.Stop()
	s.jobTickerShutdown <- true
	s.jobTickerShutdownWG.Wait()
	return nil
}

func (s *Server) runJobs() {
	s.logger.Info("running jobs...")
	ctx := context.Background()
	for _, job := range s.jobs {
		job(ctx)
	}
}

type jobFunc func(ctx context.Context)
