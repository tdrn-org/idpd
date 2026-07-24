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
	"log/slog"
	"reflect"
	"time"

	"github.com/rs/cors"
	"github.com/tdrn-org/go-conf/service/loglevel"
	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/go-httpserver/certificate"
	"github.com/tdrn-org/go-log"
	"github.com/tdrn-org/idpd/config"
	"github.com/tdrn-org/idpd/internal/userstore"
	"github.com/tdrn-org/idpd/internal/userstore/demo"
	"github.com/tdrn-org/idpd/internal/userstore/ldap"
	"github.com/tdrn-org/idpd/internal/userstore/tomlfile"
)

func applyLoggingConfig(cfg *config.LoggingConfig) {
	logConfig := &log.Config{
		Level:          cfg.Level.Value(),
		AddSource:      false,
		Target:         log.Target(cfg.Target),
		Color:          log.Color(cfg.Color),
		FileName:       cfg.FileName,
		FileSizeLimit:  cfg.FileSizeLimit,
		SyslogNetwork:  cfg.SyslogNetwork,
		SyslogAddress:  cfg.SyslogAddress,
		SyslogEncoding: cfg.SyslogEncoding,
		SyslogFacility: cfg.SyslogFacility,
		SyslogAppName:  reflect.TypeFor[Server]().PkgPath(),
	}
	logger, _ := logConfig.GetLogger(loglevel.LevelVar())
	slog.SetDefault(logger)
}

func httpServerOptions(cfg *config.ServerConfig) []httpserver.OptionSetter {
	httpServerOptions := make([]httpserver.OptionSetter, 0)
	// TLS
	if cfg.Protocol == config.ServerProtocolHttps {
		certificateProvider := &certificate.FileCertificateProvider{
			CertFile: cfg.CertFile,
			KeyFile:  cfg.KeyFile,
		}
		httpServerOptions = append(httpServerOptions, httpserver.WithCertificateProvider(certificateProvider))
	}
	// Proxy configuration
	if len(cfg.TrustedProxies) > 0 {
		httpServerOptions = append(httpServerOptions, httpserver.WithTrustedProxyPolicy(httpserver.AllowNetworks("trusted proxies", cfg.TrustedProxies.Prefixes())))
	}
	if len(cfg.TrustedHeaders) > 0 {
		httpServerOptions = append(httpServerOptions, httpserver.WithTrustedHeaders(cfg.TrustedHeaders...))
	}
	// CORS
	if len(cfg.AllowedOrigins) > 0 {
		corsOptions := &cors.Options{
			AllowedOrigins: cfg.AllowedOrigins,
		}
		httpServerOptions = append(httpServerOptions, httpserver.WithCorsOptions(corsOptions))
	}
	// Access log
	var accessLogConfig *log.Config
	switch cfg.AccessLog {
	case "stdout":
		accessLogConfig = &log.Config{
			Target: log.TargetStdout,
		}
	case "stderr":
		accessLogConfig = &log.Config{
			Target: log.TargetStderr,
		}
	case "":
		// disable Access log
	default:
		accessLogConfig = &log.Config{
			Target:        log.TargetFileText,
			FileName:      cfg.AccessLog,
			FileSizeLimit: cfg.AccessLogSizeLimit,
		}
	}
	if accessLogConfig != nil {
		accessLogLogger := slog.New(log.NewRawHandler(accessLogConfig.GetWriter()))
		httpServerOptions = append(httpServerOptions, httpserver.WithAccessLog(accessLogLogger))
	}
	return httpServerOptions
}

func ldapUserstoreConfig(cfg *config.UserstoreConfig) userstore.Config {
	attributeMapping := &cfg.LDAPConfig.CustomMapping
	switch cfg.LDAPConfig.Mapping {
	case config.LDAPMappingActiveDirectory:
		attributeMapping = ldap.ActiveDirectoryMappingConfig
	case config.LDAPMappingRFC2798:
		attributeMapping = ldap.RFC2798MappingConfig
	}
	return &ldap.Config{
		URLs:             cfg.LDAPConfig.URLs.URLs(),
		RoundRobin:       cfg.LDAPConfig.RoundRobin,
		ConnectionLimit:  cfg.LDAPConfig.ConnectionLimit,
		KeepAliveTimeout: time.Duration(cfg.LDAPConfig.KeepAliveTimeout),
		BindDN:           cfg.LDAPConfig.BindDN,
		BindPassword:     cfg.LDAPConfig.BindPassword,
		UserSearch: ldap.SearchConfig{
			BaseDN:       cfg.LDAPConfig.UserSearch.BaseDN,
			Scope:        int(cfg.LDAPConfig.UserSearch.Scope),
			DerefAliases: int(cfg.LDAPConfig.UserSearch.DerefAliases),
			Filter:       cfg.LDAPConfig.UserSearch.Filter,
		},
		UserAttributeMapping: &attributeMapping.User,
		GroupSearch: ldap.SearchConfig{
			BaseDN:       cfg.LDAPConfig.GroupSearch.BaseDN,
			Scope:        int(cfg.LDAPConfig.GroupSearch.Scope),
			DerefAliases: int(cfg.LDAPConfig.GroupSearch.DerefAliases),
			Filter:       cfg.LDAPConfig.GroupSearch.Filter,
		},
		GroupAttributeMapping: &attributeMapping.Group}
}

func fileUserstoreConfig(cfg *config.UserstoreConfig) userstore.Config {
	return &tomlfile.Config{
		File:  cfg.FileConfig.File,
		Users: cfg.FileConfig.Users,
	}
}

func demoUserstoreConfig(cfg *config.UserstoreConfig) userstore.Config {
	return &demo.Config{
		User: cfg.DemoConfig.User,
	}
}
