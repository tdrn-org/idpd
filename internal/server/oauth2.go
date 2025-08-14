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
	"github.com/tdrn-org/go-log"
	"github.com/tdrn-org/idpd/httpserver"
	"github.com/tdrn-org/idpd/internal/server/database"
	"github.com/tdrn-org/idpd/internal/server/userstore"
	"github.com/tdrn-org/idpd/internal/trace"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"go.opentelemetry.io/otel"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/text/language"
)

var ErrClientIDAlreadyRegistered = errors.New("client ID already registered")

var ErrUnknownClient = errors.New("unknown client")

var ErrInvalidClientSecret = errors.New("invalid client secret")

var ErrNoSigningKey = errors.New("no signing key")

var ErrUserNotVerified = errors.New("user not verified")

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
	CryptoKey                [32]byte
}

func (config *OAuth2ProviderConfig) NewProvider(databaseDriver database.Driver, userStore userstore.Backend, opOpts ...op.Option) (*OAuth2Provider, error) {
	provider := &OAuth2Provider{
		issuerURL:           config.IssuerURL,
		database:            databaseDriver,
		userStore:           userStore,
		signingKeyAlgorithm: config.SigningKeyAlgorithm,
		opClients:           make(map[string]opClient, 0),
		tracer:              otel.Tracer(reflect.TypeFor[OAuth2Provider]().PkgPath()),
	}
	opConfig := &op.Config{
		CryptoKey:                config.CryptoKey,
		DefaultLogoutRedirectURI: config.DefaultLogoutRedirectURL.String(),
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedUILocales:       []language.Tag{language.English},
		SupportedClaims:          op.DefaultSupportedClaims,
		SupportedScopes:          op.DefaultSupportedScopes,
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
	database            database.Driver
	userStore           userstore.Backend
	signingKeyAlgorithm jose.SignatureAlgorithm
	opClients           map[string]opClient
	opProvider          *op.Provider
	tracer              oteltrace.Tracer
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
	p.opProvider.Logger().Debug("adding OAuth2 client", slog.String("id", client.ID))
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
	p.opProvider.Logger().Info("closing OAuth2 provider")
	// Nothing to do here (yet)
	return nil
}

func (p *OAuth2Provider) Authenticate(ctx context.Context, id string, subject string, password string, verifyHandler VerifyHandler, remember bool) (string, error) {
	traceCtx, span := p.tracer.Start(ctx, "Authenticate")
	defer span.End()

	err := p.userStore.CheckPassword(subject, password)
	if err != nil {
		if !errors.Is(err, userstore.ErrInvalidLogin) {
			return "", trace.RecordError(span, err)
		}
		slog.Info("invalid OAuth2 user login", slog.String("subject", subject))
		verifyHandler.Taint()
	}
	err = p.database.AuthenticateOAuth2AuthRequest(traceCtx, id, subject, verifyHandler.GenerateChallenge, remember)
	if err != nil {
		return "", trace.RecordError(span, fmt.Errorf("invalid OAuth2 auth request id: %s (cause: %w)", id, err))
	}
	if !verifyHandler.Tainted() {
		slog.Info("OAuth2 user authenticated", slog.String("id", id), slog.String("subject", subject))
	}
	return oauth2VerifyURL(p.issuerURL, id, subject, string(verifyHandler.Method())), nil
}

func (p *OAuth2Provider) Verify(ctx context.Context, id string, subject string, verifyHandler VerifyHandler, response string) (string, error) {
	traceCtx, span := p.tracer.Start(ctx, "Verify")
	defer span.End()

	sessionRequest, err := p.database.VerifyAndTransformOAuth2AuthRequestToUserSessionRequest(traceCtx, id, subject, verifyHandler.VerifyResponse, response)
	if err != nil {
		return "", trace.RecordError(span, fmt.Errorf("OAuth2 user verification failure: %s (cause: %w)", id, err))
	}
	if sessionRequest == nil {
		return "", trace.RecordError(span, ErrUserNotVerified)
	}
	slog.Info("OAuth2 user verified", slog.String("id", id), slog.String("subject", subject))
	return op.AuthCallbackURL(p.opProvider)(traceCtx, id), nil
}

func (p *OAuth2Provider) CreateAuthRequest(ctx context.Context, oidcAuthRequest *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	traceCtx, span := p.tracer.Start(ctx, "CreateAuthRequest")
	defer span.End()

	authRequest := database.NewOAuth2AuthRequestFromOIDCAuthRequest(oidcAuthRequest, userID)
	err := p.database.InsertOAuth2AuthRequest(traceCtx, authRequest)
	if err != nil {
		return nil, trace.RecordError(span, err)
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OAuth2Provider) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	traceCtx, span := p.tracer.Start(ctx, "AuthRequestByID")
	defer span.End()

	authRequest, err := p.database.SelectOAuth2AuthRequest(traceCtx, id)
	if err != nil {
		return nil, trace.RecordError(span, err)
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OAuth2Provider) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	traceCtx, span := p.tracer.Start(ctx, "AuthRequestByCode")
	defer span.End()

	authRequest, err := p.database.SelectOAuth2AuthRequestByCode(traceCtx, code)
	if err != nil {
		return nil, trace.RecordError(span, err)
	}
	return authRequest.OpAuthRequest(), nil
}

func (p *OAuth2Provider) SaveAuthCode(ctx context.Context, id string, code string) error {
	traceCtx, span := p.tracer.Start(ctx, "SaveAuthCode")
	defer span.End()

	return trace.RecordError(span, p.database.InsertOAuth2AuthCode(traceCtx, code, id))
}

func (p *OAuth2Provider) DeleteAuthRequest(ctx context.Context, id string) error {
	traceCtx, span := p.tracer.Start(ctx, "DeleteAuthRequest")
	defer span.End()

	return trace.RecordError(span, p.database.DeleteOAuth2AuthRequest(traceCtx, id))
}

func (p *OAuth2Provider) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	traceCtx, span := p.tracer.Start(ctx, "CreateAccessToken")
	defer span.End()

	var tokenID string
	var expiry time.Time
	var err error
	switch tokenRequest := request.(type) {

	case *database.OpAuthRequest:
		tokenID, expiry, err = p.createAccessTokenFromOpAuthRequest(traceCtx, tokenRequest)
	case op.TokenExchangeRequest:
		tokenID, expiry, err = p.createAccessTokenFromTokenExchangeRequest(traceCtx, tokenRequest)
	default:
		tokenID, expiry, err = "", time.Time{}, trace.RecordError(span, fmt.Errorf("unexpected token request type: %s", reflect.TypeOf(request)))
	}
	return tokenID, expiry, trace.RecordError(span, err)
}

func (p *OAuth2Provider) createAccessTokenFromOpAuthRequest(ctx context.Context, opAuthRequest op.AuthRequest) (string, time.Time, error) {
	token := database.NewOAuth2TokenFromAuthRequest(opAuthRequest, "")
	err := p.database.InsertOAuth2Token(ctx, token)
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, time.UnixMicro(token.Expiry), nil
}

func (p *OAuth2Provider) createAccessTokenFromTokenExchangeRequest(ctx context.Context, tokenExchangeRequest op.TokenExchangeRequest) (string, time.Time, error) {
	token := database.NewOAuth2TokenFromTokenExchangeRequest(tokenExchangeRequest, "")
	err := p.database.InsertOAuth2Token(ctx, token)
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, time.UnixMicro(token.Expiry), nil
}

func (p *OAuth2Provider) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	traceCtx, span := p.tracer.Start(ctx, "CreateAccessAndRefreshTokens")
	defer span.End()

	var accessTokenID string
	var refreshTokenID string
	var expiry time.Time
	var err error
	switch refreshTokenRequest := request.(type) {
	case *database.OpAuthRequest:
		accessTokenID, refreshTokenID, expiry, err = p.createAccessAndRefreshTokenFromOpAuthRequest(traceCtx, refreshTokenRequest, currentRefreshToken)
	case op.TokenExchangeRequest:
		accessTokenID, refreshTokenID, expiry, err = p.createAccessAndRefreshTokenFromTokenExchangeRequest(traceCtx, refreshTokenRequest, currentRefreshToken)
	case op.RefreshTokenRequest:
		accessTokenID, refreshTokenID, expiry, err = p.createAccessAndRefreshTokenFromRefreshTokenRequest(traceCtx, refreshTokenRequest, currentRefreshToken)
	default:
		accessTokenID, refreshTokenID, expiry, err = "", "", time.Time{}, fmt.Errorf("unexpected refresh token request type: %s", reflect.TypeOf(request))
	}
	return accessTokenID, refreshTokenID, expiry, trace.RecordError(span, err)
}

func (p *OAuth2Provider) createAccessAndRefreshTokenFromOpAuthRequest(ctx context.Context, opAuthRequest op.AuthRequest, currentRefreshToken string) (string, string, time.Time, error) {
	var accessToken *database.OAuth2Token
	var refreshToken *database.OAuth2RefreshToken
	refreshTokenID := database.NewOAuth2RefreshTokenID()
	accessToken = database.NewOAuth2TokenFromAuthRequest(opAuthRequest, refreshTokenID)
	if currentRefreshToken == "" {
		refreshToken = database.NewOAuth2RefreshTokenFromAuthRequest(refreshTokenID, accessToken.ID, opAuthRequest)
		err := p.database.InsertOAuth2RefreshToken(ctx, refreshToken, accessToken)
		if err != nil {
			return "", "", time.Time{}, err
		}
	} else {
		newRefreshToken, err := p.database.RenewOAuth2RefreshToken(ctx, currentRefreshToken, accessToken)
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshToken = newRefreshToken
	}
	return accessToken.ID, refreshToken.ID, time.UnixMicro(accessToken.Expiry), nil
}

func (p *OAuth2Provider) createAccessAndRefreshTokenFromTokenExchangeRequest(ctx context.Context, tokenExchangeRequest op.TokenExchangeRequest, _ string) (string, string, time.Time, error) {
	refreshTokenID := database.NewOAuth2RefreshTokenID()
	accessToken := database.NewOAuth2TokenFromTokenExchangeRequest(tokenExchangeRequest, refreshTokenID)
	refreshToken := database.NewOAuth2RefreshTokenFromTokenExchangeRequest(refreshTokenID, accessToken.ID, tokenExchangeRequest)
	err := p.database.InsertOAuth2RefreshToken(ctx, refreshToken, accessToken)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return accessToken.ID, refreshToken.ID, time.UnixMicro(accessToken.Expiry), nil
}

func (p *OAuth2Provider) createAccessAndRefreshTokenFromRefreshTokenRequest(ctx context.Context, refreshTokenRequest op.RefreshTokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	var accessToken *database.OAuth2Token
	var refreshToken *database.OAuth2RefreshToken
	refreshTokenID := database.NewOAuth2RefreshTokenID()
	accessToken = database.NewOAuth2TokenFromRefreshTokenRequest(refreshTokenRequest, refreshTokenID)
	if currentRefreshToken == "" {
		refreshToken = database.NewOAuth2RefreshTokenFromRefreshTokenRequest(refreshTokenID, accessToken.ID, refreshTokenRequest)
		err := p.database.InsertOAuth2RefreshToken(ctx, refreshToken, accessToken)
		if err != nil {
			return "", "", time.Time{}, err
		}
	} else {
		newRefreshToken, err := p.database.RenewOAuth2RefreshToken(ctx, currentRefreshToken, accessToken)
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshToken = newRefreshToken
	}
	return accessToken.ID, refreshToken.ID, time.UnixMicro(accessToken.Expiry), nil
}

func (p *OAuth2Provider) TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (op.RefreshTokenRequest, error) {
	traceCtx, span := p.tracer.Start(ctx, "TokenRequestByRefreshToken")
	defer span.End()

	refreshToken, err := p.database.SelectOAuth2RefreshToken(traceCtx, refreshTokenID)
	if err != nil {
		return nil, trace.RecordError(span, err)
	}
	return refreshToken.OpRefreshToken(), nil
}

func (p *OAuth2Provider) TerminateSession(ctx context.Context, userID string, clientID string) error {
	traceCtx, span := p.tracer.Start(ctx, "TerminateSession")
	defer span.End()

	return trace.RecordError(span, p.database.DeleteOAuth2TokensBySubject(traceCtx, clientID, userID))
}

func (p *OAuth2Provider) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	traceCtx, span := p.tracer.Start(ctx, "RevokeToken")
	defer span.End()

	refreshToken, err := p.database.SelectOAuth2RefreshToken(traceCtx, tokenOrTokenID)
	if err == nil {
		if refreshToken.ClientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("refresh token was not issued for this client")
		}
		err = p.database.DeleteOAuth2RefreshToken(traceCtx, tokenOrTokenID)
		if err != nil {
			p.opProvider.Logger().Error("delete OAuth2 refresh token failure", slog.Any("err", err))
			return oidc.ErrServerError()
		}
	} else if !errors.Is(err, database.ErrObjectNotFound) {
		p.opProvider.Logger().Error("revoke OAuth2 refresh token failure", slog.Any("err", err))
		trace.RecordError(span, err)
		return oidc.ErrServerError()
	}
	token, err := p.database.SelectOAuth2Token(traceCtx, tokenOrTokenID)
	if err == nil {
		if token.ClientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		err = p.database.DeleteOAuth2Token(traceCtx, tokenOrTokenID)
		if err != nil {
			p.opProvider.Logger().Error("delete OAuth2 token failure", slog.Any("err", err))
			trace.RecordError(span, err)
			return oidc.ErrServerError()
		}
	} else if !errors.Is(err, database.ErrObjectNotFound) {
		p.opProvider.Logger().Error("revoke OAuth2 token failure", slog.Any("err", err))
		trace.RecordError(span, err)
		return oidc.ErrServerError()
	}
	return nil
}

func (p *OAuth2Provider) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	traceCtx, span := p.tracer.Start(ctx, "GetRefreshTokenInfo")
	defer span.End()

	refreshToken, err := p.database.SelectOAuth2RefreshToken(traceCtx, token)
	if errors.Is(err, database.ErrObjectNotFound) {
		return "", "", trace.RecordError(span, op.ErrInvalidRefreshToken)
	} else if err != nil {
		return "", "", trace.RecordError(span, op.ErrInvalidRefreshToken)
	} else if refreshToken.ClientID != clientID {
		return "", "", trace.RecordError(span, op.ErrInvalidRefreshToken)
	}
	return refreshToken.Subject, refreshToken.ID, nil
}

func (p *OAuth2Provider) SigningKey(ctx context.Context) (op.SigningKey, error) {
	traceCtx, span := p.tracer.Start(ctx, "SigningKey")
	defer span.End()

	now := time.Now().UnixMicro()
	signingKeys, err := p.database.RotateSigningKeys(traceCtx, p.signingKeyAlgorithm, now, database.NewSigningKeyForAlgorithm)
	if err != nil {
		return nil, trace.RecordError(span, err)
	}
	for _, signingKey := range signingKeys {
		if signingKey.Algorithm == string(p.signingKeyAlgorithm) {
			return signingKey.OpSigningKey()
		}
	}
	return nil, trace.RecordError(span, ErrNoSigningKey)
}

func (p *OAuth2Provider) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	traceCtx, span := p.tracer.Start(ctx, "SignatureAlgorithms")
	defer span.End()

	now := time.Now().UnixMicro()
	signingKeys, err := p.database.RotateSigningKeys(traceCtx, p.signingKeyAlgorithm, now, database.NewSigningKeyForAlgorithm)
	if err != nil {
		return nil, trace.RecordError(span, err)
	}
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
	traceCtx, span := p.tracer.Start(ctx, "KeySet")
	defer span.End()

	now := time.Now().UnixMicro()
	signingKeys, err := p.database.RotateSigningKeys(traceCtx, p.signingKeyAlgorithm, now, database.NewSigningKeyForAlgorithm)
	if err != nil {
		return nil, trace.RecordError(span, err)
	}
	keys := make([]op.Key, 0)
	for _, signingKey := range signingKeys {
		if signingKey.Algorithm == string(p.signingKeyAlgorithm) {
			key, err := signingKey.OpKey()
			if err != nil {
				return nil, trace.RecordError(span, err)
			}
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (p *OAuth2Provider) ClientCredentials(ctx context.Context, clientID string, clientSecret string) (op.Client, error) {
	_, span := p.tracer.Start(ctx, "ClientCredentials")
	defer span.End()

	p.logStubCall()
	return nil, nil
}
func (p *OAuth2Provider) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	_, span := p.tracer.Start(ctx, "ClientCredentialsTokenRequest")
	defer span.End()

	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	_, span := p.tracer.Start(ctx, "GetClientByClientID")
	defer span.End()

	p.mutex.RLock()
	defer p.mutex.RUnlock()
	opClient, exists := p.opClients[clientID]
	if !exists {
		return nil, trace.RecordError(span, fmt.Errorf("%w (unknown client: '%s')", ErrUnknownClient, clientID))
	}
	return &opClient, nil
}

func (p *OAuth2Provider) AuthorizeClientIDSecret(ctx context.Context, clientID string, clientSecret string) error {
	_, span := p.tracer.Start(ctx, "AuthorizeClientIDSecret")
	defer span.End()

	p.mutex.RLock()
	defer p.mutex.RUnlock()
	opClient, exists := p.opClients[clientID]
	if !exists {
		return trace.RecordError(span, fmt.Errorf("%w (unknown client: '%s')", ErrUnknownClient, clientID))
	}
	if opClient.secret != clientSecret {
		return trace.RecordError(span, fmt.Errorf("%w (invalid client secret: '%s')", ErrInvalidClientSecret, clientID))
	}
	return nil
}

func (p *OAuth2Provider) SetUserinfoFromScopes(ctx context.Context, userInfo *oidc.UserInfo, userID string, clientID string, scopes []string) error {
	_, span := p.tracer.Start(ctx, "SetUserinfoFromScopes")
	defer span.End()

	// Empty implementation; SetUserinfoFromRequest will be used instead
	return nil
}

func (p *OAuth2Provider) SetUserinfoFromRequest(ctx context.Context, userInfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	traceCtx, span := p.tracer.Start(ctx, "SetUserinfoFromRequest")
	defer span.End()

	return trace.RecordError(span, p.setUserInfoFromSubject(traceCtx, userInfo, token.GetSubject(), scopes))
}

func (p *OAuth2Provider) setUserInfoFromSubject(ctx context.Context, userInfo *oidc.UserInfo, subject string, scopes []string) error {
	_, span := p.tracer.Start(ctx, "setUserInfoFromSubject")
	defer span.End()

	user, err := p.userStore.LookupUser(subject)
	if err != nil {
		return trace.RecordError(span, err)
	}
	user.SetUserInfo(userInfo, scopes)
	return nil
}

func (p *OAuth2Provider) SetUserinfoFromToken(ctx context.Context, userInfo *oidc.UserInfo, tokenID string, subject string, origin string) error {
	traceCtx, span := p.tracer.Start(ctx, "SetUserinfoFromToken")
	defer span.End()

	token, err := p.database.SelectOAuth2Token(traceCtx, tokenID)
	if err != nil {
		return trace.RecordError(span, err)
	}
	return p.setUserInfoFromSubject(traceCtx, userInfo, token.Subject, token.Scopes)
}

func (p *OAuth2Provider) SetIntrospectionFromToken(ctx context.Context, userinfo *oidc.IntrospectionResponse, tokenID string, subject string, clientID string) error {
	_, span := p.tracer.Start(ctx, "SetIntrospectionFromToken")
	defer span.End()

	p.logStubCall()
	return nil
}

func (p *OAuth2Provider) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	_, span := p.tracer.Start(ctx, "GetPrivateClaimsFromScopes")
	defer span.End()

	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	_, span := p.tracer.Start(ctx, "GetKeyByIDAndClientID")
	defer span.End()

	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	_, span := p.tracer.Start(ctx, "ValidateJWTProfileScopes")
	defer span.End()

	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) Health(ctx context.Context) error {
	traceCtx, span := p.tracer.Start(ctx, "Health")
	defer span.End()

	logger := p.opProvider.Logger()
	log.Notice(logger, "starting health check...")
	databaseErr := p.database.Ping(traceCtx)
	if databaseErr != nil {
		logger.Error("database health: nok", slog.Any("err", databaseErr))
	} else {
		log.Notice(logger, "database health: ok")
	}
	userStoreErr := p.userStore.Ping(traceCtx)
	if userStoreErr != nil {
		logger.Error("user store health: nok", slog.Any("err", userStoreErr))
	} else {
		log.Notice(logger, "user store health: ok")
	}
	return trace.RecordError(span, errors.Join(databaseErr, userStoreErr))
}

func (p *OAuth2Provider) ValidateTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) error {
	_, span := p.tracer.Start(ctx, "ValidateTokenExchangeRequest")
	defer span.End()

	p.logStubCall()
	return nil
}

func (p *OAuth2Provider) CreateTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) error {
	_, span := p.tracer.Start(ctx, "CreateTokenExchangeRequest")
	defer span.End()

	p.logStubCall()
	return nil
}

func (p *OAuth2Provider) GetPrivateClaimsFromTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) (claims map[string]any, err error) {
	_, span := p.tracer.Start(ctx, "GetPrivateClaimsFromTokenExchangeRequest")
	defer span.End()

	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) SetUserinfoFromTokenExchangeRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.TokenExchangeRequest) error {
	_, span := p.tracer.Start(ctx, "SetUserinfoFromTokenExchangeRequest")
	defer span.End()

	p.logStubCall()
	return nil
}

func (p *OAuth2Provider) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	_, span := p.tracer.Start(ctx, "StoreDeviceAuthorization")
	defer span.End()

	p.logStubCall()
	return nil
}

func (p *OAuth2Provider) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	_, span := p.tracer.Start(ctx, "GetDeviceAuthorizatonState")
	defer span.End()

	p.logStubCall()
	return nil, nil
}

func (p *OAuth2Provider) logStubCall() {
	_, file, line, _ := runtime.Caller(1)
	p.opProvider.Logger().Warn("stub call", slog.String("location", fmt.Sprintf("%s:%d", file, line)))
}
