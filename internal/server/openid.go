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

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/tdrn-org/idpd/httpserver"
	"github.com/tdrn-org/idpd/internal/server/database"
	"github.com/tdrn-org/idpd/internal/server/userstore"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

type OpenIDClient struct {
	ID           string
	Secret       string
	RedirectURIs []string
}

type opClient struct {
	id                             string
	secret                         string
	redirectURIs                   []string
	postLogoutRedirectURIs         []string
	applicationType                op.ApplicationType
	authMethod                     oidc.AuthMethod
	responseTypes                  []oidc.ResponseType
	grantTypes                     []oidc.GrantType
	loginURLPattern                string
	accessTokenType                op.AccessTokenType
	idTokenLifetime                time.Duration
	devMode                        bool
	idTokenUserinfoClaimsAssertion bool
	clockSkew                      time.Duration
}

func (c *opClient) GetID() string {
	return c.id
}

func (c *opClient) GetSecret() string {
	return c.secret
}

func (c *opClient) RedirectURIs() []string {
	return c.redirectURIs
}

func (c *opClient) PostLogoutRedirectURIs() []string {
	return c.postLogoutRedirectURIs
}

func (c *opClient) ApplicationType() op.ApplicationType {
	return c.applicationType
}

func (c *opClient) AuthMethod() oidc.AuthMethod {
	return c.authMethod
}

func (c *opClient) ResponseTypes() []oidc.ResponseType {
	return c.responseTypes
}

func (c *opClient) GrantTypes() []oidc.GrantType {
	return c.grantTypes
}

func (c *opClient) LoginURL(user string) string {
	return fmt.Sprintf(c.loginURLPattern, url.QueryEscape(user))
}

func (c *opClient) AccessTokenType() op.AccessTokenType {
	return c.accessTokenType
}

func (c *opClient) IDTokenLifetime() time.Duration {
	return c.idTokenLifetime
}

func (c *opClient) DevMode() bool {
	return c.devMode
}

func (c *opClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *opClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *opClient) IsScopeAllowed(scope string) bool {
	return true
}

func (c *opClient) IDTokenUserinfoClaimsAssertion() bool {
	return c.idTokenUserinfoClaimsAssertion
}

func (c *opClient) ClockSkew() time.Duration {
	return c.clockSkew
}

type OpenIDProviderConfig struct {
	Issuer                   string
	DefaultLogoutRedirectURI string
	SigningKeyAlgorithm      jose.SignatureAlgorithm
	SigningKeyLifetime       time.Duration
	SigningKeyExpiry         time.Duration
}

func (config *OpenIDProviderConfig) NewProvider(driver database.Driver, backend userstore.Backend, opOpts ...op.Option) (*OpenIDProvider, error) {
	logger := slog.With(slog.String("issuer", config.Issuer))
	provider := &OpenIDProvider{
		driver:              driver,
		backend:             backend,
		signingKeyAlgorithm: config.SigningKeyAlgorithm,
		signingKeyLifetime:  config.SigningKeyLifetime,
		signingKeyExpiry:    config.SigningKeyExpiry,
		opClients:           make(map[string]opClient, 0),
		logger:              logger,
	}
	opConfig := &op.Config{
		CryptoKey:                sha256.Sum256([]byte(rand.Text())),
		DefaultLogoutRedirectURI: config.DefaultLogoutRedirectURI,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    false,
		RequestObjectSupported:   false,
		SupportedUILocales:       []language.Tag{language.English},
		SupportedClaims:          []string{"openid", "profile", "email", "groups"},
		SupportedScopes:          []string{"openid", "profile", "email", "groups"},
		DeviceAuthorization:      op.DeviceAuthorizationConfig{
			// TODO
		},
		BackChannelLogoutSupported:        false,
		BackChannelLogoutSessionSupported: false,
	}
	opProvider, err := op.NewProvider(opConfig, provider, op.StaticIssuer(config.Issuer), opOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenID provider (cause: %w)", err)
	}
	provider.opProvider = opProvider
	return provider, nil
}

type OpenIDProvider struct {
	driver              database.Driver
	backend             userstore.Backend
	signingKeyAlgorithm jose.SignatureAlgorithm
	signingKeyLifetime  time.Duration
	signingKeyExpiry    time.Duration
	opClients           map[string]opClient
	opProvider          *op.Provider
	logger              *slog.Logger
	mutex               sync.RWMutex
}

func (p *OpenIDProvider) AddClient(client *OpenIDClient, loginURLPattern string) error {
	opClient := &opClient{
		id:                             client.ID,
		secret:                         client.Secret,
		redirectURIs:                   client.RedirectURIs,
		postLogoutRedirectURIs:         []string{},
		applicationType:                op.ApplicationTypeNative,
		authMethod:                     oidc.AuthMethodNone,
		responseTypes:                  []oidc.ResponseType{oidc.ResponseTypeCode},
		grantTypes:                     []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken},
		loginURLPattern:                loginURLPattern,
		accessTokenType:                op.AccessTokenTypeBearer,
		idTokenLifetime:                1 * time.Hour,
		devMode:                        false,
		idTokenUserinfoClaimsAssertion: false,
		clockSkew:                      0,
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	_, exists := p.opClients[opClient.id]
	if exists {

	}
	p.opClients[opClient.id] = *opClient
	return nil
}

func (p *OpenIDProvider) Mount(handler httpserver.Handler) *OpenIDProvider {
	handler.HandleFunc("/healthz", p.opProvider.ServeHTTP)
	handler.HandleFunc("/ready", p.opProvider.ServeHTTP)
	handler.HandleFunc("/.well-known/openid-configuration", p.opProvider.ServeHTTP)
	handler.HandleFunc("/authorize/callback", p.opProvider.ServeHTTP)
	handler.HandleFunc("/authorize", p.opProvider.ServeHTTP)
	handler.HandleFunc("/oauth/token", p.opProvider.ServeHTTP)
	handler.HandleFunc("/oauth/introspect", p.opProvider.ServeHTTP)
	handler.HandleFunc("/userinfo", p.opProvider.ServeHTTP)
	handler.HandleFunc("/revoke", p.opProvider.ServeHTTP)
	handler.HandleFunc("/end_session", p.opProvider.ServeHTTP)
	handler.HandleFunc("/keys", p.opProvider.ServeHTTP)
	handler.HandleFunc("/device_authorization", p.opProvider.ServeHTTP)
	return p
}

func (p *OpenIDProvider) Close() error {
	// Nothing to do here (yet)
	return nil
}

func (p *OpenIDProvider) Authenticate(ctx context.Context, id string, email string, password string, remember bool) (string, error) {
	err := p.backend.CheckPassword(email, password)
	if err != nil {
		return "", err
	}
	_, err = p.driver.AuthenticateAndTransformAuthRequestToUserSessionRequest(ctx, id, email, remember)
	if err != nil {
		return "", fmt.Errorf("invalid auth request id: %s", id)
	}
	slog.Info("user authenticated", slog.String("id", id), slog.String("email", email))
	return op.AuthCallbackURL(p.opProvider)(ctx, id), nil
}

func (p *OpenIDProvider) CreateAuthRequest(ctx context.Context, oidcAuthRequest *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	authRequest := &database.AuthRequest{
		ID:            uuid.NewString(),
		ACR:           "",
		AMR:           []string{"pwd"},
		Audience:      []string{oidcAuthRequest.ClientID},
		CreateTime:    time.Now().UnixMicro(),
		ClientID:      oidcAuthRequest.ClientID,
		CodeChallenge: nil,
		Nonce:         oidcAuthRequest.Nonce,
		RedirectURI:   oidcAuthRequest.RedirectURI,
		ResponseType:  oidcAuthRequest.ResponseType,
		ResponseMode:  oidcAuthRequest.ResponseMode,
		Scopes:        oidcAuthRequest.Scopes,
		State:         oidcAuthRequest.State,
		Subject:       userID,
		Done:          false,
	}
	if oidcAuthRequest.CodeChallenge != "" {
		authRequest.CodeChallenge = &oidc.CodeChallenge{
			Challenge: oidcAuthRequest.CodeChallenge,
			Method:    oidcAuthRequest.CodeChallengeMethod,
		}
	}
	err := p.driver.InsertAuthRequest(ctx, authRequest)
	if err != nil {
		return nil, err
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OpenIDProvider) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	authRequest, err := p.driver.SelectAuthRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OpenIDProvider) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	authRequest, err := p.driver.SelectAuthRequestByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OpenIDProvider) SaveAuthCode(ctx context.Context, id string, code string) error {
	return p.driver.InsertAuthCode(ctx, code, id)
}

func (p *OpenIDProvider) DeleteAuthRequest(ctx context.Context, id string) error {
	return p.driver.DeleteAuthRequest(ctx, id)
}

func (p *OpenIDProvider) CreateAccessToken(ctx context.Context, tokenRequest op.TokenRequest) (string, time.Time, error) {
	switch request := tokenRequest.(type) {
	case *database.OpAuthRequest:
		return p.createAccessTokenFromOpAuthRequest(ctx, request)
	case op.TokenExchangeRequest:
		return p.createAccessTokenFromTokenExchangeRequest(ctx, request)
	}
	return "", time.Time{}, fmt.Errorf("unexpected token request type: %s", reflect.TypeOf(tokenRequest))
}

func (p *OpenIDProvider) createAccessTokenFromOpAuthRequest(ctx context.Context, opAuthRequest op.AuthRequest) (string, time.Time, error) {
	token := &database.Token{
		ID:             uuid.NewString(),
		ApplicationID:  opAuthRequest.GetClientID(),
		Subject:        opAuthRequest.GetSubject(),
		RefreshTokenID: "",
		Audience:       opAuthRequest.GetAudience(),
		Expiration:     time.Now().Add(5 * time.Minute).UnixMicro(),
		Scopes:         opAuthRequest.GetScopes(),
	}
	err := p.driver.InsertToken(ctx, token)
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, time.UnixMicro(token.Expiration), nil
}

func (p *OpenIDProvider) createAccessTokenFromTokenExchangeRequest(ctx context.Context, tokenExchangeRequest op.TokenExchangeRequest) (string, time.Time, error) {
	token := &database.Token{
		ID:             uuid.NewString(),
		ApplicationID:  tokenExchangeRequest.GetClientID(),
		Subject:        tokenExchangeRequest.GetSubject(),
		RefreshTokenID: "",
		Audience:       tokenExchangeRequest.GetAudience(),
		Expiration:     time.Now().Add(5 * time.Minute).UnixMicro(),
		Scopes:         tokenExchangeRequest.GetScopes(),
	}
	err := p.driver.InsertToken(ctx, token)
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, time.UnixMicro(token.Expiration), nil
}

func (p *OpenIDProvider) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshTokenID string, expiration time.Time, err error) {
	p.logStubCall()
	return "", "", time.Now(), nil
}

func (p *OpenIDProvider) TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (op.RefreshTokenRequest, error) {
	p.logStubCall()
	return nil, nil
}

func (p *OpenIDProvider) TerminateSession(ctx context.Context, userID string, clientID string) error {
	p.logStubCall()
	return nil
}

func (p *OpenIDProvider) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	p.logStubCall()
	return nil
}

func (p *OpenIDProvider) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	p.logStubCall()
	return "", "", nil
}

func (p *OpenIDProvider) generateSigningKey(algorithm string) (*database.SigningKey, error) {
	now := time.Now()
	passivation := now.Add(p.signingKeyLifetime).UnixMicro()
	expiration := now.Add(p.signingKeyExpiry).UnixMicro()
	return SigningKeyForAlgorithm(jose.SignatureAlgorithm(algorithm), passivation, expiration)
}

var ErrNoSigningKey = errors.New("no signing key")

func (p *OpenIDProvider) SigningKey(ctx context.Context) (op.SigningKey, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	signingKeys, err := p.driver.RotateSigningKeys(ctx, string(p.signingKeyAlgorithm), p.generateSigningKey)
	if err != nil {
		return nil, err
	}
	for _, signingKey := range signingKeys {
		if signingKey.Algorithm == string(p.signingKeyAlgorithm) {
			return signingKey.OpSigningKey()
		}
	}
	return nil, ErrNoSigningKey
}

func (p *OpenIDProvider) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	signingKeys, err := p.driver.RotateSigningKeys(ctx, string(p.signingKeyAlgorithm), p.generateSigningKey)
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMicro()
	algorithms := make(map[string]jose.SignatureAlgorithm, 0)
	for _, signingKey := range signingKeys {
		if !signingKey.IsActive(now) {
			break
		}
		algorithms[signingKey.Algorithm] = jose.SignatureAlgorithm(signingKey.Algorithm)
	}
	return slices.Collect(maps.Values(algorithms)), nil
}

func (p *OpenIDProvider) KeySet(ctx context.Context) ([]op.Key, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	signingKeys, err := p.driver.RotateSigningKeys(ctx, string(p.signingKeyAlgorithm), p.generateSigningKey)
	if err != nil {
		return nil, err
	}
	keys := make([]op.Key, 0)
	for _, signingKey := range signingKeys {
		if signingKey.Algorithm == string(p.signingKeyAlgorithm) {
			key, err := signingKey.OpKey()
			if err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (p *OpenIDProvider) ClientCredentials(ctx context.Context, clientID string, clientSecret string) (op.Client, error) {
	p.logStubCall()
	return nil, nil
}
func (p *OpenIDProvider) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	p.logStubCall()
	return nil, nil
}

func (p *OpenIDProvider) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	opClient, exists := p.opClients[clientID]
	if !exists {
		return nil, fmt.Errorf("unknown client '%s'", clientID)
	}
	return &opClient, nil
}

func (p *OpenIDProvider) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	p.logStubCall()
	return nil
}

func (p *OpenIDProvider) SetUserinfoFromScopes(ctx context.Context, userInfo *oidc.UserInfo, userID string, clientID string, scopes []string) error {
	// Empty implementation; SetUserinfoFromRequest will be used instead
	return nil
}

func (p *OpenIDProvider) SetUserinfoFromRequest(ctx context.Context, userInfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	user, err := p.backend.LookupUserByEmail(token.GetSubject())
	if err != nil {
		return err
	}
	user.SetUserInfo(userInfo, scopes)
	return nil
}

func (p *OpenIDProvider) SetUserinfoFromToken(ctx context.Context, userInfo *oidc.UserInfo, tokenID string, subject string, origin string) error {
	token, err := p.driver.SelectToken(ctx, tokenID)
	if err != nil {
		return err
	}
	userInfo.Subject = token.Subject
	return nil
}

func (p *OpenIDProvider) SetIntrospectionFromToken(ctx context.Context, userinfo *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	p.logStubCall()
	return nil
}

func (p *OpenIDProvider) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	p.logStubCall()
	return nil, nil
}

func (p *OpenIDProvider) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	p.logStubCall()
	return nil, nil
}

func (p *OpenIDProvider) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	p.logStubCall()
	return nil, nil
}

func (p *OpenIDProvider) Health(context.Context) error {
	p.logStubCall()
	return nil
}

func (p *OpenIDProvider) logStubCall() {
	_, file, line, _ := runtime.Caller(0)
	p.logger.Warn("stub call", slog.String("location", fmt.Sprintf("%s:%d", file, line)))
}
