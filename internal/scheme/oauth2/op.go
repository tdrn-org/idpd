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
	"net/url"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/tdrn-org/idpd/config"
	"github.com/tdrn-org/idpd/internal/domain"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type opSigningKey struct {
	signingKey *domain.SigningKey
}

func (k *opSigningKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return k.signingKey.Algorithm
}
func (k *opSigningKey) Key() any {
	return k.signingKey.Key
}

func (k *opSigningKey) ID() string {
	return k.signingKey.ID
}

type opClient struct {
	cfg      *config.OAuth2ClientConfig
	loginURL *url.URL
}

func (c *opClient) GetID() string {
	return c.cfg.ID
}

func (c *opClient) RedirectURIs() []string {
	return c.cfg.RedirectURLStrings()
}

func (c *opClient) PostLogoutRedirectURIs() []string {
	return c.cfg.PostLogoutURLStrings()
}

func (c *opClient) ApplicationType() op.ApplicationType {
	return op.ApplicationType(c.cfg.ClientType)
}

func (c *opClient) AuthMethod() oidc.AuthMethod {
	return oidc.AuthMethod(c.cfg.AuthMethod)
}

func (c *opClient) ResponseTypes() []oidc.ResponseType {
	return c.cfg.ResponseTypeValues()
}

func (c *opClient) GrantTypes() []oidc.GrantType {
	return c.cfg.GrantTypeValues()
}

func (c *opClient) LoginURL(id string) string {
	loginURL := *c.loginURL
	query := loginURL.Query()
	query.Set("id", id)
	loginURL.RawQuery = query.Encode()
	return loginURL.String()
}

func (c *opClient) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenType(c.cfg.AccessTokenType)
}

func (c *opClient) IDTokenLifetime() time.Duration {
	return time.Duration(c.cfg.IDTokenLifetime)
}

func (c *opClient) DevMode() bool {
	return false
}

func (c *opClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return c.allowedScopes
}

func (c *opClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return c.allowedScopes
}

func (c *opClient) allowedScopes(scopes []string) []string {
	allowed := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if c.IsScopeAllowed(scope) {
			allowed = append(allowed, scope)
		}
	}
	return allowed
}

func (c *opClient) IsScopeAllowed(scope string) bool {
	return slices.Contains(c.cfg.AllowedScopes, scope)
}

func (c *opClient) IDTokenUserinfoClaimsAssertion() bool {
	return !c.cfg.StrictMode
}

func (c *opClient) ClockSkew() time.Duration {
	return DefaultClientClockSkew
}
