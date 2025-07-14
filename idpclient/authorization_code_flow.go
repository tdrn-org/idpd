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

package idpclient

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdrn-org/idpd/httpserver"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

type AuthorizationCodeFlowConfig[C oidc.IDClaims] struct {
	BaseURI         string
	AuthURIPath     string
	RedirectURIPath string
	Issuer          string
	ClientId        string
	ClientSecret    string
	Scopes          []string
	EnablePKCE      bool
}

func (config *AuthorizationCodeFlowConfig[C]) NewFlow(httpClient *http.Client, ctx context.Context, codeExchangeCallback rp.CodeExchangeCallback[C]) (*AuthorizationCodeFlow[C], error) {
	parsedBaseURI, err := url.Parse(config.BaseURI)
	if err != nil {
		return nil, fmt.Errorf("invalid base URI '%s' (cause: %w)", config.BaseURI, err)
	}
	authURI := parsedBaseURI.JoinPath(config.AuthURIPath)
	redirectURI := parsedBaseURI.JoinPath(config.RedirectURIPath)
	cookieHandler, err := NewCookieHandler(parsedBaseURI)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie handler (cause: %w)", err)
	}
	logger := slog.With(slog.String("client", config.ClientId), slog.String("issuer", config.Issuer))
	options := []rp.Option{
		rp.WithHTTPClient(httpClient),
		rp.WithCookieHandler(cookieHandler),
		rp.WithLogger(logger),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithSigningAlgsFromDiscovery(),
	}
	if config.ClientSecret == "" || config.EnablePKCE {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	providerFunc := sync.OnceValues(func() (rp.RelyingParty, error) {
		provider, err := rp.NewRelyingPartyOIDC(ctx, config.Issuer, config.ClientId, config.ClientSecret, redirectURI.String(), config.Scopes, options...)
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenID provider (cause: %w)", err)
		}
		return provider, nil
	})
	flow := &AuthorizationCodeFlow[C]{
		authURI:              authURI,
		redirectURI:          redirectURI,
		providerFunc:         providerFunc,
		codeExchangeCallback: codeExchangeCallback,
		logger:               slog.With(slog.String("redirectURI", redirectURI.String()), slog.String("client", config.ClientId)),
	}
	return flow, nil
}

type AuthorizationCodeFlow[C oidc.IDClaims] struct {
	authURI              *url.URL
	redirectURI          *url.URL
	providerFunc         func() (rp.RelyingParty, error)
	codeExchangeCallback rp.CodeExchangeCallback[C]
	logger               *slog.Logger
}

func (flow *AuthorizationCodeFlow[C]) Mount(handler httpserver.Handler) *AuthorizationCodeFlow[C] {
	handler.HandleFunc("/"+flow.authURI.Path, flow.authHandler)
	handler.HandleFunc("/"+flow.redirectURI.Path, flow.redirectHandler)
	return flow
}

func (flow *AuthorizationCodeFlow[C]) authHandler(w http.ResponseWriter, r *http.Request) {
	provider, err := flow.providerFunc()
	if err != nil {
		flow.logger.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	rp.AuthURLHandler(uuid.NewString, provider).ServeHTTP(w, r)
}

func (flow *AuthorizationCodeFlow[C]) redirectHandler(w http.ResponseWriter, r *http.Request) {
	provider, err := flow.providerFunc()
	if err != nil {
		flow.logger.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	rp.CodeExchangeHandler(flow.codeExchangeCallback, provider)(w, r)
}

func (flow *AuthorizationCodeFlow[C]) AuthURI() *url.URL {
	return flow.authURI
}

func (flow *AuthorizationCodeFlow[C]) Client(ctx context.Context, token *oauth2.Token) (*http.Client, error) {
	provider, err := flow.providerFunc()
	if err != nil {
		return nil, err
	}
	return provider.OAuthConfig().Client(ctx, token), nil
}

func (flow *AuthorizationCodeFlow[C]) GetEndSessionEndpoint() (string, error) {
	provider, err := flow.providerFunc()
	if err != nil {
		return "", err
	}
	return provider.GetEndSessionEndpoint(), nil
}

func (flow *AuthorizationCodeFlow[C]) GetRevokeEndpoint() (string, error) {
	provider, err := flow.providerFunc()
	if err != nil {
		return "", err
	}
	return provider.GetRevokeEndpoint(), nil
}

func (flow *AuthorizationCodeFlow[C]) UserinfoEndpoint() (string, error) {
	provider, err := flow.providerFunc()
	if err != nil {
		return "", err
	}
	return provider.UserinfoEndpoint(), nil
}

func (flow *AuthorizationCodeFlow[C]) GetDeviceAuthorizationEndpoint() (string, error) {
	provider, err := flow.providerFunc()
	if err != nil {
		return "", err
	}
	return provider.GetDeviceAuthorizationEndpoint(), nil
}
