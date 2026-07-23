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

package oauth2client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/tdrn-org/idpd/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/oauth2"
)

func NewOIDCCodeFlowClientConfig(id, secret string, public bool, redirectURL *url.URL) *config.OAuth2ClientConfig {
	clientType := op.ApplicationTypeUserAgent
	clientSecret := ""
	authMethod := oidc.AuthMethodNone
	if !public {
		clientType = op.ApplicationTypeWeb
		clientSecret = secret
		authMethod = oidc.AuthMethodBasic
	}
	clientConfig := &config.OAuth2ClientConfig{
		ID:     id,
		Name:   id,
		Secret: clientSecret,
		RedirectURLs: config.URLSpecs{
			{URL: redirectURL},
		},
		ClientType: config.OAuth2ClientType(clientType),
		AuthMethod: config.OAuth2AuthMethod(authMethod),
		ResponseTypes: []config.OAuth2ResponseType{
			config.OAuth2ResponseType(oidc.ResponseTypeCode),
		},
		GrantTypes: []config.OAuth2GrantType{
			config.OAuth2GrantType(oidc.GrantTypeCode),
		},
		AllowedScopes: []string{
			oidc.ScopeOpenID,
			oidc.ScopeProfile,
			oidc.ScopeEmail,
		},
		AccessTokenType: config.OAuth2AccessTokenType(op.AccessTokenTypeBearer),
		IDTokenLifetime: config.DurationSpec(DefaultIDTokenLifetime),
		StrictMode:      true,
	}
	return clientConfig
}

type OIDCCodeFlow struct {
	oauth2Config oauth2.Config
}

func NewOIDCCodeFLow(config *oauth2.Config) *OIDCCodeFlow {
	return &OIDCCodeFlow{
		oauth2Config: *config,
	}
}

func (f *OIDCCodeFlow) Init(ctx context.Context) (string, *NonceSessionData, error) {
	state := randString(32)
	nonce := randString(32)
	url := f.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("nonce", nonce))
	sessionData := &NonceSessionData{
		State: state,
		Nonce: nonce,
	}
	return url, sessionData, nil
}

func (f *OIDCCodeFlow) Callback(ctx context.Context, req *http.Request, session *NonceSessionData) (*TokenAuthResult, error) {
	if req.URL.Query().Get("state") != session.State {
		return nil, http.ErrAbortHandler
	}
	code := req.URL.Query().Get("code")
	token, err := f.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	authResult := &TokenAuthResult{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}
	return authResult, nil
}
