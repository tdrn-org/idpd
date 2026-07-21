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

package oauth2

import (
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/config"
	"github.com/tdrn-org/idpd/internal/i18n"
	"github.com/tdrn-org/idpd/internal/scheme"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/oauth2"
)

const Name scheme.Name = "oauth2"

const DefaultSigningKeyActiveDuration time.Duration = 30 * 24 * time.Hour
const DefaultSigningKeyLifetimeDuration time.Duration = 60 * 24 * time.Hour
const DefaultClientClockSkew time.Duration = 1 * time.Minute

const (
	authorizationEndpoint = "/" + string(Name) + "/authorize"
	authCallbackEndpoint  = authorizationEndpoint + "/callback"
	tokenEndpoint         = "/" + string(Name) + "/token"
	introspectEndpoint    = "/" + string(Name) + "/introspect"
	userinfoEndpoint      = "/" + string(Name) + "/userinfo"
	revocationEndpoint    = "/" + string(Name) + "/revoke"
	endSessionEndpoint    = "/" + string(Name) + "/end_session"
	keysEndpoint          = "/" + string(Name) + "/keys"

	deviceAuthzEndpoint = "/device_authorization"

	loginEndpoint = "/" + string(Name) + "/login"
)

type Handler struct {
	runtime    scheme.Runtime
	cfg        *config.OAuth2Config
	opProvider *op.Provider
	clients    map[string]*opClient
	logger     *slog.Logger
	mutex      sync.RWMutex
}

func NewHandler(runtime scheme.Runtime, cfg *config.OAuth2Config) (*Handler, error) {
	logger := runtime.Logger().With("scheme", Name)
	h := &Handler{
		runtime: runtime,
		cfg:     cfg,
		clients: make(map[string]*opClient),
		logger:  logger,
	}
	opConfig := &op.Config{
		DefaultLogoutRedirectURI:          h.runtime.BaseURL().String(),
		CodeMethodS256:                    true,
		AuthMethodPost:                    true,
		AuthMethodPrivateKeyJWT:           true,
		GrantTypeRefreshToken:             true,
		RequestObjectSupported:            true,
		SupportedUILocales:                i18n.SupportedLocales,
		SupportedClaims:                   filterClaims(h.cfg.Claims, h.logger),
		SupportedScopes:                   filterScopes(h.cfg.Scopes, h.logger),
		DeviceAuthorization:               op.DeviceAuthorizationConfig{},
		BackChannelLogoutSupported:        true,
		BackChannelLogoutSessionSupported: true,
	}
	opStorage := &opStorage{handler: h}
	issuerURL := h.runtime.BaseURL()
	opOptions := []op.Option{
		op.WithLogger(h.logger),
		op.WithCrypto(&opCrypto{handler: h}),
		op.WithCustomEndpoints(
			op.NewEndpoint(authorizationEndpoint),
			op.NewEndpoint(tokenEndpoint),
			op.NewEndpoint(userinfoEndpoint),
			op.NewEndpoint(revocationEndpoint),
			op.NewEndpoint(endSessionEndpoint),
			op.NewEndpoint(keysEndpoint),
		),
		op.WithCustomIntrospectionEndpoint(op.NewEndpoint(introspectEndpoint)),
		op.WithCustomDeviceAuthorizationEndpoint(op.NewEndpoint(deviceAuthzEndpoint)),
		allowInsecure(issuerURL),
	}
	opProvider, err := op.NewProvider(
		opConfig,
		opStorage,
		op.StaticIssuer(issuerURL.String()),
		opOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth2 OP provider (cause: %w)", err)
	}
	h.opProvider = opProvider
	return h, nil
}

func (h *Handler) Name() scheme.Name {
	return Name
}

func (h *Handler) Mount(instance *httpserver.Instance) {
	instance.Handle(oidc.DiscoveryEndpoint, h.opProvider)
	instance.Handle(authorizationEndpoint, h.opProvider)
	instance.Handle(authCallbackEndpoint, h.opProvider)
	instance.Handle(tokenEndpoint, h.opProvider)
	instance.Handle(introspectEndpoint, h.opProvider)
	instance.Handle(userinfoEndpoint, h.opProvider)
	instance.Handle(revocationEndpoint, h.opProvider)
	instance.Handle(endSessionEndpoint, h.opProvider)
	instance.Handle(keysEndpoint, h.opProvider)
	instance.Handle(deviceAuthzEndpoint, h.opProvider)
}

func (h *Handler) Endpoint() *oauth2.Endpoint {
	issuerURL := h.runtime.BaseURL()
	return &oauth2.Endpoint{
		AuthURL:       issuerURL.JoinPath(authorizationEndpoint).String(),
		DeviceAuthURL: issuerURL.JoinPath(deviceAuthzEndpoint).String(),
		TokenURL:      issuerURL.JoinPath(tokenEndpoint).String(),
	}
}

func (h *Handler) AddClient(cfg *config.OAuth2ClientConfig) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.logger.Info("adding OAuth2 client", slog.String("id", cfg.ID), slog.Any("redirectURLs", cfg.RedirectURLStrings()))
	h.clients[cfg.ID] = &opClient{
		cfg:      cfg,
		loginURL: h.runtime.BaseURL().JoinPath(loginEndpoint),
	}
}

func filterClaims(claims []string, logger *slog.Logger) []string {
	supportedClaims := op.DefaultSupportedClaims
	if len(claims) == 0 {
		return supportedClaims
	}
	filteredClaims := make([]string, 0, len(claims))
	for _, claim := range claims {
		if !slices.Contains(supportedClaims, claim) {
			logger.Warn("ignoring unsupported claim", slog.String("claim", claim))
			continue
		}
		filteredClaims = append(filteredClaims, claim)
	}
	return filteredClaims
}

func filterScopes(scopes []string, logger *slog.Logger) []string {
	supportedScopes := op.DefaultSupportedScopes
	if len(scopes) == 0 {
		return supportedScopes
	}
	filteredScopes := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !slices.Contains(supportedScopes, scope) {
			logger.Warn("ignoring unsupported scope", slog.String("scope", scope))
			continue
		}
		filteredScopes = append(filteredScopes, scope)
	}
	return filteredScopes
}

func allowInsecure(issuerURL *url.URL) op.Option {
	noop := func(_ *op.Provider) error { return nil }
	if issuerURL.Scheme == "https" {
		return noop
	}
	host := strings.ToLower(issuerURL.Hostname())
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return op.WithAllowInsecure()
	}
	return noop
}
