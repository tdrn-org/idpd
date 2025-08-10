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

package oauth2client

import (
	"context"
	"encoding/json"
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

const clientGetFailure = "client Get operation failure (cause: %w)"

type AuthorizationCodeFlowConfig[C oidc.IDClaims] struct {
	BaseURL         string
	AuthURLPath     string
	RedirectURLPath string
	Issuer          string
	ClientId        string
	ClientSecret    string
	Scopes          []string
	EnablePKCE      bool
}

type CodeExchangeCallback[C oidc.IDClaims] func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], state string, flow *AuthorizationCodeFlow[C])

func (config *AuthorizationCodeFlowConfig[C]) NewFlow(httpClient *http.Client, ctx context.Context, codeExchangeCallback CodeExchangeCallback[C]) (*AuthorizationCodeFlow[C], error) {
	parsedBaseURL, err := url.Parse(config.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL '%s' (cause: %w)", config.BaseURL, err)
	}
	authURL := config.resolveAuthURL(parsedBaseURL)
	redirectURL := config.resolveRedirectURL(parsedBaseURL)
	cookieHandler := newCookieHandler(parsedBaseURL)
	logger := slog.With(slog.String("client", config.ClientId), slog.String("issuer", config.Issuer))
	options := make([]rp.Option, 5, 6)
	options[0] = rp.WithHTTPClient(httpClient)
	options[1] = rp.WithCookieHandler(cookieHandler)
	options[2] = rp.WithLogger(logger)
	options[3] = rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second))
	options[4] = rp.WithSigningAlgsFromDiscovery()
	if config.ClientSecret == "" || config.EnablePKCE {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	providerFunc := sync.OnceValues(func() (rp.RelyingParty, error) {
		provider, err := rp.NewRelyingPartyOIDC(ctx, config.Issuer, config.ClientId, config.ClientSecret, redirectURL.String(), config.Scopes, options...)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider (cause: %w)", err)
		}
		return provider, nil
	})
	flow := &AuthorizationCodeFlow[C]{
		authURL:              authURL,
		redirectURL:          redirectURL,
		providerFunc:         providerFunc,
		codeExchangeCallback: codeExchangeCallback,
		logger:               slog.With(slog.String("client", config.ClientId), slog.Any("redirectURL", redirectURL)),
	}
	return flow, nil
}

func (c *AuthorizationCodeFlowConfig[C]) resolveAuthURL(baseURL *url.URL) *url.URL {
	if c.AuthURLPath != "" {
		return baseURL.JoinPath(c.AuthURLPath)
	}
	return baseURL.JoinPath("/authenticate")
}

func (c *AuthorizationCodeFlowConfig[C]) resolveRedirectURL(baseURL *url.URL) *url.URL {
	if c.RedirectURLPath != "" {
		return baseURL.JoinPath(c.RedirectURLPath)
	}
	return baseURL.JoinPath("/authorized")
}

type AuthorizationCodeFlow[C oidc.IDClaims] struct {
	authURL              *url.URL
	redirectURL          *url.URL
	providerFunc         func() (rp.RelyingParty, error)
	codeExchangeCallback CodeExchangeCallback[C]
	logger               *slog.Logger
}

func (flow *AuthorizationCodeFlow[C]) Mount(handler httpserver.Handler) *AuthorizationCodeFlow[C] {
	handler.HandleFunc("/"+flow.authURL.Path, flow.authHandler)
	handler.HandleFunc("/"+flow.redirectURL.Path, flow.redirectHandler)
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
	rp.CodeExchangeHandler(flow.codeExchange, provider)(w, r)
}

func (flow *AuthorizationCodeFlow[C]) codeExchange(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], state string, _ rp.RelyingParty) {
	flow.codeExchangeCallback(w, r, tokens, state, flow)
}

func (flow *AuthorizationCodeFlow[C]) Authenticate() error {
	provider, err := flow.providerFunc()
	if err != nil {
		return err
	}
	rsp, err := provider.HttpClient().Get(flow.authURL.String())
	if err != nil {
		return fmt.Errorf("failed to initiate authorization code flow (cause: %w)", err)
	}
	switch rsp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		return fmt.Errorf("authentication code flow failed: %s", rsp.Status)
	}
}

func (flow *AuthorizationCodeFlow[C]) TokenSource(ctx context.Context, token *oauth2.Token) (oauth2.TokenSource, error) {
	provider, err := flow.providerFunc()
	if err != nil {
		return nil, err
	}
	return provider.OAuthConfig().TokenSource(ctx, token), nil
}

func (flow *AuthorizationCodeFlow[C]) Client(ctx context.Context, token *oauth2.Token) (*http.Client, error) {
	provider, err := flow.providerFunc()
	if err != nil {
		return nil, err
	}
	return provider.OAuthConfig().Client(ctx, token), nil
}

func (flow *AuthorizationCodeFlow[C]) GetEndSessionEndpoint() string {
	provider, err := flow.providerFunc()
	if err != nil {
		return ""
	}
	return provider.GetEndSessionEndpoint()
}

func (flow *AuthorizationCodeFlow[C]) GetRevokeEndpoint() string {
	provider, err := flow.providerFunc()
	if err != nil {
		return ""
	}
	return provider.GetRevokeEndpoint()
}

func (flow *AuthorizationCodeFlow[C]) UserinfoEndpoint() string {
	provider, err := flow.providerFunc()
	if err != nil {
		return ""
	}
	return provider.UserinfoEndpoint()
}

func (flow *AuthorizationCodeFlow[C]) GetUserInfo(client *http.Client, ctx context.Context) (*oidc.UserInfo, error) {
	provider, err := flow.providerFunc()
	if err != nil {
		return nil, err
	}
	userInfoResponse, err := client.Get(provider.UserinfoEndpoint())
	if err != nil {
		return nil, fmt.Errorf(clientGetFailure, err)
	}
	if userInfoResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info endpoint failure (status: %s)", userInfoResponse.Status)
	}
	defer userInfoResponse.Body.Close()
	userInfo := &oidc.UserInfo{}
	err = json.NewDecoder(userInfoResponse.Body).Decode(userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user info endpoint response (cause: %w)", err)
	}
	return userInfo, nil
}

func (flow *AuthorizationCodeFlow[C]) GetDeviceAuthorizationEndpoint() string {
	provider, err := flow.providerFunc()
	if err != nil {
		return ""
	}
	return provider.GetDeviceAuthorizationEndpoint()
}
