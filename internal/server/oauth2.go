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
	"github.com/tdrn-org/idpd/httpserver"
	"github.com/tdrn-org/idpd/internal/server/database"
	"github.com/tdrn-org/idpd/internal/server/userstore"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

var ErrClientIDAlreadyRegistered = errors.New("client ID already registered")

var ErrUnknownClient = errors.New("unknown client")

var ErrInvalidClientSecret = errors.New("invalid client secret")

var ErrNoSigningKey = errors.New("no signing key")

type OAuth2Client struct {
	ID           string
	Secret       string
	RedirectURLs []string
}

type opClient struct {
	id                             string
	secret                         string
	redirectURLs                   []string
	postLogoutRedirectURLs         []string
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
	return c.redirectURLs
}

func (c *opClient) PostLogoutRedirectURIs() []string {
	return c.postLogoutRedirectURLs
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

type OAuth2ProviderConfig struct {
	Issuer                   string
	DefaultLogoutRedirectURL string
	SigningKeyAlgorithm      jose.SignatureAlgorithm
	SigningKeyLifetime       time.Duration
	SigningKeyExpiry         time.Duration
}

func (config *OAuth2ProviderConfig) NewProvider(driver database.Driver, backend userstore.Backend, opOpts ...op.Option) (*OAuth2Provider, error) {
	logger := slog.With(slog.String("issuer", config.Issuer))
	provider := &OAuth2Provider{
		issuerURL:           config.Issuer,
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
		DefaultLogoutRedirectURI: config.DefaultLogoutRedirectURL,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    false,
		RequestObjectSupported:   false,
		SupportedUILocales:       []language.Tag{language.English},
		SupportedClaims:          []string{},
		SupportedScopes:          []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess, "groups"},
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

type OAuth2Provider struct {
	issuerURL           string
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

const defaultClockSkew = 10 * time.Second
const defaultIDTokenLifetime = 1 * time.Hour

func (p *OAuth2Provider) AddClient(client *OAuth2Client) error {
	opClient := &opClient{
		id:                             client.ID,
		secret:                         client.Secret,
		redirectURLs:                   client.RedirectURLs,
		postLogoutRedirectURLs:         []string{},
		applicationType:                op.ApplicationTypeNative,
		authMethod:                     oidc.AuthMethodNone,
		responseTypes:                  []oidc.ResponseType{oidc.ResponseTypeCode},
		grantTypes:                     []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken},
		loginURLPattern:                p.issuerURL + "/user?id=%s",
		accessTokenType:                op.AccessTokenTypeBearer,
		idTokenLifetime:                defaultIDTokenLifetime,
		devMode:                        false,
		idTokenUserinfoClaimsAssertion: false,
		clockSkew:                      defaultClockSkew,
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	_, exists := p.opClients[opClient.id]
	if exists {
		return fmt.Errorf("%w (client ID '%s' already registered)", ErrClientIDAlreadyRegistered, opClient.id)
	}
	p.opClients[opClient.id] = *opClient
	return nil
}

func (p *OAuth2Provider) Mount(handler httpserver.Handler) *OAuth2Provider {
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

func (p *OAuth2Provider) Close() error {
	// Nothing to do here (yet)
	return nil
}

func (p *OAuth2Provider) Authenticate(ctx context.Context, id string, email string, password string, remember bool) (string, error) {
	slog.Info("authenticating user", slog.String("id", id), slog.String("email", email))
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

func (p *OAuth2Provider) CreateAuthRequest(ctx context.Context, oidcAuthRequest *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	authRequest := database.NewAuthRequestFromOIDCAuthRequest(oidcAuthRequest, userID)
	err := p.driver.InsertAuthRequest(ctx, authRequest)
	if err != nil {
		return nil, err
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OAuth2Provider) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	authRequest, err := p.driver.SelectAuthRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OAuth2Provider) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	authRequest, err := p.driver.SelectAuthRequestByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OAuth2Provider) SaveAuthCode(ctx context.Context, id string, code string) error {
	return p.driver.InsertAuthCode(ctx, code, id)
}

func (p *OAuth2Provider) DeleteAuthRequest(ctx context.Context, id string) error {
	return p.driver.DeleteAuthRequest(ctx, id)
}

func (p *OAuth2Provider) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	switch tokenRequest := request.(type) {
	case *database.OpAuthRequest:
		return p.createAccessTokenFromOpAuthRequest(ctx, tokenRequest)
	case op.TokenExchangeRequest:
		return p.createAccessTokenFromTokenExchangeRequest(ctx, tokenRequest)
	}
	return "", time.Time{}, fmt.Errorf("unexpected token request type: %s", reflect.TypeOf(request))
}

func (p *OAuth2Provider) createAccessTokenFromOpAuthRequest(ctx context.Context, opAuthRequest op.AuthRequest) (string, time.Time, error) {
	token := database.NewTokenFromAuthRequest(opAuthRequest, "")
	err := p.driver.InsertToken(ctx, token)
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, time.UnixMicro(token.Expiration), nil
}

func (p *OAuth2Provider) createAccessTokenFromTokenExchangeRequest(ctx context.Context, tokenExchangeRequest op.TokenExchangeRequest) (string, time.Time, error) {
	token := database.NewTokenFromTokenExchangeRequest(tokenExchangeRequest, "")
	err := p.driver.InsertToken(ctx, token)
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, time.UnixMicro(token.Expiration), nil
}

func (p *OAuth2Provider) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	switch refreshTokenRequest := request.(type) {
	case *database.OpAuthRequest:
		return p.createAccessAndRefreshTokenFromOpAuthRequest(ctx, refreshTokenRequest, currentRefreshToken)
	case op.TokenExchangeRequest:
		p.logStubCall()
		return "", "", time.Time{}, nil
	case op.RefreshTokenRequest:
		p.logStubCall()
		return "", "", time.Time{}, nil
	}
	return "", "", time.Time{}, fmt.Errorf("unexpected refresh token request type: %s", reflect.TypeOf(request))
}

func (p *OAuth2Provider) createAccessAndRefreshTokenFromOpAuthRequest(ctx context.Context, opAuthRequest op.AuthRequest, currentRefreshToken string) (string, string, time.Time, error) {
	var accessToken *database.Token
	var refreshToken *database.RefreshToken
	refreshTokenID := database.NewRefreshTokenID()
	accessToken = database.NewTokenFromAuthRequest(opAuthRequest, refreshTokenID)
	if currentRefreshToken == "" {
		refreshToken = database.NewRefreshTokenFromAuthRequest(refreshTokenID, accessToken.ID, opAuthRequest)
		err := p.driver.InsertRefreshToken(ctx, refreshToken, accessToken)
		if err != nil {
			return "", "", time.Time{}, err
		}
	} else {
		newRefreshToken, err := p.driver.RenewRefreshToken(ctx, refreshTokenID, accessToken)
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshToken = newRefreshToken
	}
	return accessToken.ID, refreshToken.ID, time.UnixMicro(accessToken.Expiration), nil
}

func (p *OAuth2Provider) TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (op.RefreshTokenRequest, error) {
	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) TerminateSession(ctx context.Context, userID string, clientID string) error {
	p.logStubCall()
	return nil
}

func (p *OAuth2Provider) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	p.logStubCall()
	return nil
}

func (p *OAuth2Provider) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	refreshToken, err := p.driver.SelectRefreshToken(ctx, token)
	if errors.Is(err, database.ErrObjectNotFound) {
		return "", "", op.ErrInvalidRefreshToken
	} else if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	} else if refreshToken.ApplicationID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return refreshToken.UserID, refreshToken.ID, nil
}

func (p *OAuth2Provider) SigningKey(ctx context.Context) (op.SigningKey, error) {
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

func (p *OAuth2Provider) generateSigningKey(algorithm string) (*database.SigningKey, error) {
	now := time.Now()
	passivation := now.Add(p.signingKeyLifetime).UnixMicro()
	expiration := now.Add(p.signingKeyExpiry).UnixMicro()
	return SigningKeyForAlgorithm(jose.SignatureAlgorithm(algorithm), passivation, expiration)
}

func (p *OAuth2Provider) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
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

func (p *OAuth2Provider) KeySet(ctx context.Context) ([]op.Key, error) {
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

func (p *OAuth2Provider) ClientCredentials(ctx context.Context, clientID string, clientSecret string) (op.Client, error) {
	p.logStubCall()
	return nil, nil
}
func (p *OAuth2Provider) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	opClient, exists := p.opClients[clientID]
	if !exists {
		return nil, fmt.Errorf("%w (unknown client: '%s')", ErrUnknownClient, clientID)
	}
	return &opClient, nil
}

func (p *OAuth2Provider) AuthorizeClientIDSecret(ctx context.Context, clientID string, clientSecret string) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	opClient, exists := p.opClients[clientID]
	if !exists {
		return fmt.Errorf("%w (unknown client: '%s')", ErrUnknownClient, clientID)
	}
	if opClient.secret != clientSecret {
		return fmt.Errorf("%w (invalid client secret: '%s')", ErrInvalidClientSecret, clientID)
	}
	return nil
}

func (p *OAuth2Provider) SetUserinfoFromScopes(ctx context.Context, userInfo *oidc.UserInfo, userID string, clientID string, scopes []string) error {
	// Empty implementation; SetUserinfoFromRequest will be used instead
	return nil
}

func (p *OAuth2Provider) SetUserinfoFromRequest(ctx context.Context, userInfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	return p.setUserInfoFromSubject(ctx, userInfo, token.GetSubject(), scopes)
}

func (p *OAuth2Provider) setUserInfoFromSubject(_ context.Context, userInfo *oidc.UserInfo, subject string, scopes []string) error {
	user, err := p.backend.LookupUserByEmail(subject)
	if err != nil {
		return err
	}
	user.SetUserInfo(userInfo, scopes)
	return nil
}

func (p *OAuth2Provider) SetUserinfoFromToken(ctx context.Context, userInfo *oidc.UserInfo, tokenID string, subject string, origin string) error {
	token, err := p.driver.SelectToken(ctx, tokenID)
	if err != nil {
		return err
	}
	return p.setUserInfoFromSubject(ctx, userInfo, token.Subject, token.Scopes)
}

func (p *OAuth2Provider) SetIntrospectionFromToken(ctx context.Context, userinfo *oidc.IntrospectionResponse, tokenID string, subject string, clientID string) error {
	p.logStubCall()
	return nil
}

func (p *OAuth2Provider) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) Health(context.Context) error {
	p.logStubCall()
	return nil
}

func (p *OAuth2Provider) logStubCall() {
	_, file, line, _ := runtime.Caller(1)
	p.logger.Warn("stub call", slog.String("location", fmt.Sprintf("%s:%d", file, line)))
}
