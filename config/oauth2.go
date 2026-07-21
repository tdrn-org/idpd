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

package config

import (
	"fmt"
	"log/slog"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type OAuth2Config struct {
	Enabled             bool                 `toml:"enabled"`
	Claims              []string             `toml:"claims"`
	Scopes              []string             `toml:"scopes"`
	SigningKeyAlgorithm SignatureAlgorithm   `toml:"signing_key_algorithm"`
	Clients             []OAuth2ClientConfig `toml:"client"`
}

type OAuth2ClientConfig struct {
	ID              string                `toml:"id"`
	Name            string                `toml:"name"`
	Secret          string                `toml:"secret"`
	RedirectURLs    URLSpecs              `toml:"redirect_urls"`
	PostLogoutURLs  URLSpecs              `toml:"post_logout_urls"`
	ClientType      OAuth2ClientType      `toml:"client_type"`
	AuthMethod      OAuth2AuthMethod      `toml:"auth_method"`
	ResponseTypes   []OAuth2ResponseType  `toml:"response_types"`
	GrantTypes      []OAuth2GrantType     `toml:"grant_types"`
	AllowedScopes   []string              `toml:"allowed_scopes"`
	AccessTokenType OAuth2AccessTokenType `toml:"access_token_type"`
	IDTokenLifetime DurationSpec          `toml:"id_token_lifetime"`
	StrictMode      bool                  `toml:"strict_mode"`
}

func (c *OAuth2ClientConfig) RedirectURLStrings() []string {
	strings := make([]string, 0, len(c.RedirectURLs))
	for _, url := range c.RedirectURLs {
		strings = append(strings, url.String())
	}
	return strings
}

func (c *OAuth2ClientConfig) PostLogoutURLStrings() []string {
	strings := make([]string, 0, len(c.PostLogoutURLs))
	for _, url := range c.PostLogoutURLs {
		strings = append(strings, url.String())
	}
	return strings
}

func (c *OAuth2ClientConfig) ResponseTypeValues() []oidc.ResponseType {
	values := make([]oidc.ResponseType, 0, len(c.ResponseTypes))
	for _, responseType := range c.ResponseTypes {
		values = append(values, oidc.ResponseType(responseType))
	}
	return values
}

func (c *OAuth2ClientConfig) GrantTypeValues() []oidc.GrantType {
	values := make([]oidc.GrantType, 0, len(c.GrantTypes))
	for _, grantType := range c.GrantTypes {
		values = append(values, oidc.GrantType(grantType))
	}
	return values
}

type SignatureAlgorithm jose.SignatureAlgorithm

var knownSignatureAlgorithms map[string]SignatureAlgorithm = map[string]SignatureAlgorithm{
	string(jose.EdDSA): SignatureAlgorithm(jose.EdDSA),
	string(jose.HS256): SignatureAlgorithm(jose.HS256),
	string(jose.HS384): SignatureAlgorithm(jose.HS384),
	string(jose.HS512): SignatureAlgorithm(jose.HS512),
	string(jose.RS256): SignatureAlgorithm(jose.RS256),
	string(jose.RS384): SignatureAlgorithm(jose.RS384),
	string(jose.RS512): SignatureAlgorithm(jose.RS512),
	string(jose.ES256): SignatureAlgorithm(jose.ES256),
	string(jose.ES384): SignatureAlgorithm(jose.ES384),
	string(jose.ES512): SignatureAlgorithm(jose.ES512),
	string(jose.PS256): SignatureAlgorithm(jose.PS256),
	string(jose.PS384): SignatureAlgorithm(jose.PS384),
	string(jose.PS512): SignatureAlgorithm(jose.PS512),
}

func (a *SignatureAlgorithm) Value() string {
	for value, signatureAlgorithm := range knownSignatureAlgorithms {
		if *a == signatureAlgorithm {
			return value
		}
	}
	slog.Warn("unexpected signature algorithm", slog.Any("a", *a))
	return ""
}

func (a *SignatureAlgorithm) MarshalTOML() ([]byte, error) {
	return []byte(`"` + a.Value() + `"`), nil
}

func (a *SignatureAlgorithm) UnmarshalTOML(value any) error {
	signatureAlgorithmString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected signature algorithm type %v", value)
	}
	signatureAlgorithm, ok := knownSignatureAlgorithms[signatureAlgorithmString]
	if !ok {
		return fmt.Errorf("unknown signature algorihm: '%s'", signatureAlgorithmString)
	}
	*a = signatureAlgorithm
	return nil
}

type OAuth2ClientType op.ApplicationType

var knownOAuth2ClientTypes map[string]OAuth2ClientType = map[string]OAuth2ClientType{
	string("web"):        OAuth2ClientType(op.ApplicationTypeWeb),
	string("user_agent"): OAuth2ClientType(op.ApplicationTypeUserAgent),
	string("native"):     OAuth2ClientType(op.ApplicationTypeNative),
}

func (t *OAuth2ClientType) Value() string {
	for value, clientType := range knownOAuth2ClientTypes {
		if *t == clientType {
			return value
		}
	}
	slog.Warn("unexpected OAuth2 client type", slog.Any("t", *t))
	return ""
}

func (t *OAuth2ClientType) MarshalTOML() ([]byte, error) {
	return []byte(`"` + t.Value() + `"`), nil
}

func (t *OAuth2ClientType) UnmarshalTOML(value any) error {
	clientTypeString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected OAuth2 client type type %v", value)
	}
	clientType, ok := knownOAuth2ClientTypes[clientTypeString]
	if !ok {
		return fmt.Errorf("unknown OAuth2 client type: '%s'", clientTypeString)
	}
	*t = clientType
	return nil
}

type OAuth2AuthMethod oidc.AuthMethod

var knownOAuth2AuthMethods map[string]OAuth2AuthMethod = map[string]OAuth2AuthMethod{
	string(oidc.AuthMethodBasic):         OAuth2AuthMethod(oidc.AuthMethodBasic),
	string(oidc.AuthMethodPost):          OAuth2AuthMethod(oidc.AuthMethodPost),
	string(oidc.AuthMethodNone):          OAuth2AuthMethod(oidc.AuthMethodNone),
	string(oidc.AuthMethodPrivateKeyJWT): OAuth2AuthMethod(oidc.AuthMethodPrivateKeyJWT),
}

func (m *OAuth2AuthMethod) Value() string {
	for value, authMethod := range knownOAuth2AuthMethods {
		if *m == authMethod {
			return value
		}
	}
	slog.Warn("unexpected OAuth2 auth method", slog.Any("m", *m))
	return ""
}

func (m *OAuth2AuthMethod) MarshalTOML() ([]byte, error) {
	return []byte(`"` + m.Value() + `"`), nil
}

func (m *OAuth2AuthMethod) UnmarshalTOML(value any) error {
	authMethodString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected OAuth2 auth method type %v", value)
	}
	authMethod, ok := knownOAuth2AuthMethods[authMethodString]
	if !ok {
		return fmt.Errorf("unknown OAuth2 auth method: '%s'", authMethodString)
	}
	*m = authMethod
	return nil
}

type OAuth2ResponseType oidc.ResponseType

var knownOAuth2ResponseTypes map[string]OAuth2ResponseType = map[string]OAuth2ResponseType{
	string(oidc.ResponseTypeCode):        OAuth2ResponseType(oidc.ResponseTypeCode),
	string(oidc.ResponseTypeIDToken):     OAuth2ResponseType(oidc.ResponseTypeIDToken),
	string(oidc.ResponseTypeIDTokenOnly): OAuth2ResponseType(oidc.ResponseTypeIDTokenOnly),
}

func (t *OAuth2ResponseType) Value() string {
	for value, responseType := range knownOAuth2ResponseTypes {
		if *t == responseType {
			return value
		}
	}
	slog.Warn("unexpected OAuth2 response type", slog.Any("t", *t))
	return ""
}

func (t *OAuth2ResponseType) MarshalTOML() ([]byte, error) {
	return []byte(`"` + t.Value() + `"`), nil
}

func (t *OAuth2ResponseType) UnmarshalTOML(value any) error {
	responseTypeString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected OAuth2 response type type %v", value)
	}
	responseType, ok := knownOAuth2ResponseTypes[responseTypeString]
	if !ok {
		return fmt.Errorf("unknown OAuth2 response type: '%s'", responseTypeString)
	}
	*t = responseType
	return nil
}

type OAuth2GrantType oidc.GrantType

var knownOAuth2GrantTypes map[string]OAuth2GrantType = map[string]OAuth2GrantType{
	string(oidc.GrantTypeCode):                   OAuth2GrantType(oidc.GrantTypeCode),
	string(oidc.GrantTypeRefreshToken):           OAuth2GrantType(oidc.GrantTypeRefreshToken),
	string(oidc.GrantTypeClientCredentials):      OAuth2GrantType(oidc.GrantTypeClientCredentials),
	string(oidc.GrantTypeBearer):                 OAuth2GrantType(oidc.GrantTypeBearer),
	string(oidc.GrantTypeTokenExchange):          OAuth2GrantType(oidc.GrantTypeTokenExchange),
	string(oidc.GrantTypeImplicit):               OAuth2GrantType(oidc.GrantTypeImplicit),
	string(oidc.GrantTypeDeviceCode):             OAuth2GrantType(oidc.GrantTypeDeviceCode),
	string(oidc.ClientAssertionTypeJWTAssertion): OAuth2GrantType(oidc.ClientAssertionTypeJWTAssertion),
}

func (t *OAuth2GrantType) Value() string {
	for value, grantType := range knownOAuth2GrantTypes {
		if *t == grantType {
			return value
		}
	}
	slog.Warn("unexpected OAuth2 response type", slog.Any("t", *t))
	return ""
}

func (t *OAuth2GrantType) MarshalTOML() ([]byte, error) {
	return []byte(`"` + t.Value() + `"`), nil
}

func (t *OAuth2GrantType) UnmarshalTOML(value any) error {
	grantTypeString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected OAuth2 response type type %v", value)
	}
	grantType, ok := knownOAuth2GrantTypes[grantTypeString]
	if !ok {
		return fmt.Errorf("unknown OAuth2 response type: '%s'", grantTypeString)
	}
	*t = grantType
	return nil
}

type OAuth2AccessTokenType op.AccessTokenType

var knownOAuth2AccessTokenTypes map[string]OAuth2AccessTokenType = map[string]OAuth2AccessTokenType{
	"bearer": OAuth2AccessTokenType(op.AccessTokenTypeBearer),
	"jwt":    OAuth2AccessTokenType(op.AccessTokenTypeJWT),
}

func (t *OAuth2AccessTokenType) Value() string {
	for value, accessTokenType := range knownOAuth2AccessTokenTypes {
		if *t == accessTokenType {
			return value
		}
	}
	slog.Warn("unexpected OAuth2 access token type", slog.Any("t", *t))
	return ""
}

func (t *OAuth2AccessTokenType) MarshalTOML() ([]byte, error) {
	return []byte(`"` + t.Value() + `"`), nil
}

func (t *OAuth2AccessTokenType) UnmarshalTOML(value any) error {
	accessTokenTypeString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected OAuth2 access token type type %v", value)
	}
	accessTokenType, ok := knownOAuth2AccessTokenTypes[accessTokenTypeString]
	if !ok {
		return fmt.Errorf("unknown OAuth2 access token type: '%s'", accessTokenTypeString)
	}
	*t = accessTokenType
	return nil
}
