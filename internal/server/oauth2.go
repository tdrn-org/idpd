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
	issuerURL                      *url.URL
	redirectURLs                   []string
	postLogoutRedirectURLs         []string
	applicationType                op.ApplicationType
	authMethod                     oidc.AuthMethod
	responseTypes                  []oidc.ResponseType
	grantTypes                     []oidc.GrantType
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

func (c *opClient) LoginURL(id string) string {
	return oauth2LoginURL(c.issuerURL, id)
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
	IssuerURL                *url.URL
	DefaultLogoutRedirectURL *url.URL
	SigningKeyAlgorithm      jose.SignatureAlgorithm
	SigningKeyLifetime       time.Duration
	SigningKeyExpiry         time.Duration
}

func (config *OAuth2ProviderConfig) NewProvider(driver database.Driver, backend userstore.Backend, opOpts ...op.Option) (*OAuth2Provider, error) {
	logger := slog.With(slog.String("issuer", config.IssuerURL.String()))
	provider := &OAuth2Provider{
		issuerURL:           config.IssuerURL,
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
		DefaultLogoutRedirectURI: config.DefaultLogoutRedirectURL.String(),
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
	opProvider, err := op.NewProvider(opConfig, provider, op.StaticIssuer(config.IssuerURL.String()), opOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth2 provider (cause: %w)", err)
	}
	provider.opProvider = opProvider
	return provider, nil
}

type OAuth2Provider struct {
	issuerURL           *url.URL
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

func oauth2LoginURL(issuerURL *url.URL, id string) string {
	url := issuerURL.JoinPath("/user")
	query := url.Query()
	query.Add("id", id)
	url.RawQuery = query.Encode()
	return url.String()
}

func oauth2VerifyURL(issuerURL *url.URL, id string, subject string, verification string) string {
	url := issuerURL.JoinPath("/user/verify")
	query := url.Query()
	query.Add("id", id)
	query.Add("subject", subject)
	query.Add("verification", verification)
	url.RawQuery = query.Encode()
	return url.String()
}

const defaultClockSkew = 10 * time.Second
const defaultIDTokenLifetime = 1 * time.Hour

func (p *OAuth2Provider) AddClient(client *OAuth2Client) error {
	p.logger.Debug("adding OAuth2 client", slog.String("id", client.ID))
	opClient := &opClient{
		id:                             client.ID,
		secret:                         client.Secret,
		issuerURL:                      p.issuerURL,
		redirectURLs:                   client.RedirectURLs,
		postLogoutRedirectURLs:         []string{},
		applicationType:                op.ApplicationTypeNative,
		authMethod:                     oidc.AuthMethodNone,
		responseTypes:                  []oidc.ResponseType{oidc.ResponseTypeCode},
		grantTypes:                     []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken},
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
	p.logger.Info("closing OAuth2 provider")
	// Nothing to do here (yet)
	return nil
}

func (p *OAuth2Provider) Authenticate(ctx context.Context, id string, subject string, password string, verifyHandler VerifyHandler, remember bool) (string, error) {
	slog.Info("authenticating OAuth2 user", slog.String("id", id), slog.String("subject", subject), slog.String("verification", string(verifyHandler.Method())))
	err := p.backend.CheckPassword(subject, password)
	if err != nil {
		if !errors.Is(err, userstore.ErrInvalidLogin) {
			return "", err
		}
		slog.Info("invalid OAuth2 user login", slog.String("subject", subject))
		verifyHandler.Taint()
	}
	err = p.driver.AuthenticateOAuth2AuthRequest(ctx, id, subject, verifyHandler.GenerateChallenge, remember)
	if err != nil {
		return "", fmt.Errorf("invalid OAuth2 auth request id: %s (cause: %w)", id, err)
	}
	if !verifyHandler.Tainted() {
		slog.Info("OAuth2 user authenticated", slog.String("id", id), slog.String("subject", subject))
	}
	return oauth2VerifyURL(p.issuerURL, id, subject, string(verifyHandler.Method())), nil
}

func (p *OAuth2Provider) Verify(ctx context.Context, id string, subject string, verifyHandler VerifyHandler, response string) (string, error) {
	slog.Info("verifying OAuth2 user", slog.String("id", id), slog.String("subject", subject), slog.String("verification", string(verifyHandler.Method())))

	// TODO: Integrate VerifyHandler
	_, err := p.driver.VerifyAndTransformOAuth2AuthRequestToUserSessionRequest(ctx, id, subject, verifyHandler.VerifyResponse, response)
	if err != nil {
		return "", fmt.Errorf("OAuth2 verification failure: %s (cause: %w)", id, err)
	}
	slog.Info("OAuth2 user verified", slog.String("id", id), slog.String("subject", subject))
	return op.AuthCallbackURL(p.opProvider)(ctx, id), nil
}

func (p *OAuth2Provider) CreateAuthRequest(ctx context.Context, oidcAuthRequest *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	authRequest := database.NewOAuth2AuthRequestFromOIDCAuthRequest(oidcAuthRequest, userID)
	err := p.driver.InsertOAuth2AuthRequest(ctx, authRequest)
	if err != nil {
		return nil, err
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OAuth2Provider) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	authRequest, err := p.driver.SelectOAuth2AuthRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OAuth2Provider) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	authRequest, err := p.driver.SelectOAuth2AuthRequestByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OAuth2Provider) SaveAuthCode(ctx context.Context, id string, code string) error {
	return p.driver.InsertOAuth2AuthCode(ctx, code, id)
}

func (p *OAuth2Provider) DeleteAuthRequest(ctx context.Context, id string) error {
	return p.driver.DeleteOAuth2AuthRequest(ctx, id)
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
	token := database.NewOAuth2TokenFromAuthRequest(opAuthRequest, "")
	err := p.driver.InsertOAuth2Token(ctx, token)
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, time.UnixMicro(token.Expiration), nil
}

func (p *OAuth2Provider) createAccessTokenFromTokenExchangeRequest(ctx context.Context, tokenExchangeRequest op.TokenExchangeRequest) (string, time.Time, error) {
	token := database.NewOAuth2TokenFromTokenExchangeRequest(tokenExchangeRequest, "")
	err := p.driver.InsertOAuth2Token(ctx, token)
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
	var accessToken *database.OAuth2Token
	var refreshToken *database.OAuth2RefreshToken
	refreshTokenID := database.NewOAuth2RefreshTokenID()
	accessToken = database.NewOAuth2TokenFromAuthRequest(opAuthRequest, refreshTokenID)
	if currentRefreshToken == "" {
		refreshToken = database.NewOAuth2RefreshTokenFromAuthRequest(refreshTokenID, accessToken.ID, opAuthRequest)
		err := p.driver.InsertOAuth2RefreshToken(ctx, refreshToken, accessToken)
		if err != nil {
			return "", "", time.Time{}, err
		}
	} else {
		newRefreshToken, err := p.driver.RenewOAuth2RefreshToken(ctx, refreshTokenID, accessToken)
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshToken = newRefreshToken
	}
	return accessToken.ID, refreshToken.ID, time.UnixMicro(accessToken.Expiration), nil
}

func (p *OAuth2Provider) TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (op.RefreshTokenRequest, error) {
	refreshToken, err := p.driver.SelectOAuth2RefreshToken(ctx, refreshTokenID)
	if err != nil {
		return nil, err
	}
	return refreshToken.OpRefreshToken(), nil
}

func (p *OAuth2Provider) TerminateSession(ctx context.Context, userID string, clientID string) error {
	return p.driver.DeleteOAuth2TokensBySubject(ctx, clientID, userID)
}

func (p *OAuth2Provider) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	refreshToken, err := p.driver.SelectOAuth2RefreshToken(ctx, tokenOrTokenID)
	if err == nil {
		if refreshToken.ClientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("refresh token was not issued for this client")
		}
		err = p.driver.DeleteOAuth2RefreshToken(ctx, tokenOrTokenID)
		if err != nil {
			p.logger.Error("delete OAuth2 refresh token failure", slog.Any("err", err))
			return oidc.ErrServerError()
		}
	} else if !errors.Is(err, database.ErrObjectNotFound) {
		p.logger.Error("revoke OAuth2 refresh token failure", slog.Any("err", err))
		return oidc.ErrServerError()
	}
	token, err := p.driver.SelectOAuth2Token(ctx, tokenOrTokenID)
	if err == nil {
		if token.ClientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		err = p.driver.DeleteOAuth2Token(ctx, tokenOrTokenID)
		if err != nil {
			p.logger.Error("delete OAuth2 token failure", slog.Any("err", err))
			return oidc.ErrServerError()
		}
	} else if !errors.Is(err, database.ErrObjectNotFound) {
		p.logger.Error("revoke OAuth2 token failure", slog.Any("err", err))
		return oidc.ErrServerError()
	}
	return nil
}

func (p *OAuth2Provider) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	refreshToken, err := p.driver.SelectOAuth2RefreshToken(ctx, token)
	if errors.Is(err, database.ErrObjectNotFound) {
		return "", "", op.ErrInvalidRefreshToken
	} else if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	} else if refreshToken.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return refreshToken.Subject, refreshToken.ID, nil
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
	user, err := p.backend.LookupUser(subject)
	if err != nil {
		return err
	}
	user.SetUserInfo(userInfo, scopes)
	return nil
}

func (p *OAuth2Provider) SetUserinfoFromToken(ctx context.Context, userInfo *oidc.UserInfo, tokenID string, subject string, origin string) error {
	token, err := p.driver.SelectOAuth2Token(ctx, tokenID)
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
