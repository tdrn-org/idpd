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
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/scheme/oauth2/model"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type opStorage struct {
	handler *Handler
}

// op.AuthStorage
func (s *opStorage) CreateAuthRequest(ctx context.Context, oidcAuthRequest *oidc.AuthRequest, idTokenHintUserID string) (op.AuthRequest, error) {
	dataStore := s.handler.runtime.DataStore()
	var opAuthRequest op.AuthRequest
	err := s.handler.runtime.DataStore().Atomic(ctx, func(txCtx context.Context, tx *database.Tx) error {
		userSessionRequest, err := dataStore.CreateUserSessionRequest(txCtx, s.handler.Name().String())
		if err != nil {
			return err
		}
		authRequest, err := model.InsertAuthRequest(txCtx, tx, userSessionRequest, oidcAuthRequest)
		if err != nil {
			return err
		}
		opAuthRequest = authRequest.OpAuthRequest()
		return nil
	})
	return opAuthRequest, err
}

// op.AuthStorage
func (s *opStorage) AuthRequestByID(context.Context, string) (op.AuthRequest, error) {
	s.logStub()
	return nil, nil
}

// op.AuthStorage
func (s *opStorage) AuthRequestByCode(context.Context, string) (op.AuthRequest, error) {
	s.logStub()
	return nil, nil
}

// op.AuthStorage
func (s *opStorage) SaveAuthCode(context.Context, string, string) error {
	s.logStub()
	return nil
}

// op.AuthStorage
func (s *opStorage) DeleteAuthRequest(context.Context, string) error {
	s.logStub()
	return nil
}

// op.AuthStorage
func (s *opStorage) CreateAccessToken(context.Context, op.TokenRequest) (accessTokenID string, expiration time.Time, err error) {
	s.logStub()
	return "", time.Time{}, nil
}

// op.AuthStorage
func (s *opStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	s.logStub()
	return "", "", time.Time{}, nil
}

// op.AuthStorage
func (s *opStorage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	s.logStub()
	return nil, nil
}

// op.AuthStorage
func (s *opStorage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	s.logStub()
	return nil
}

// op.AuthStorage
func (s *opStorage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	s.logStub()
	return nil
}

// op.AuthStorage
func (s *opStorage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	s.logStub()
	return "", "", nil
}

// op.AuthStorage
func (s *opStorage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	signingKey, err := s.handler.runtime.DataStore().GetSigningKey(ctx, jose.SignatureAlgorithm(s.handler.cfg.SigningKeyAlgorithm), DefaultSigningKeyActiveDuration, DefaultSigningKeyLifetimeDuration)
	if err != nil {
		return nil, err
	}
	return &opSigningKey{signingKey: signingKey}, nil
}

// op.AuthStorage
func (s *opStorage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.SignatureAlgorithm(s.handler.cfg.SigningKeyAlgorithm)}, nil
}

// op.AuthStorage
func (s *opStorage) KeySet(context.Context) ([]op.Key, error) {
	s.logStub()
	return nil, nil
}

// op.CanTerminateSessionFromRequest
func (s *opStorage) TerminateSessionFromRequest(ctx context.Context, endSessionRequest *op.EndSessionRequest) (string, error) {
	s.logStub()
	return "", nil
}

// op.ClientCredentialsStorage
func (s *opStorage) ClientCredentials(ctx context.Context, clientID, clientSecret string) (op.Client, error) {
	s.logStub()
	return nil, nil
}

// op.ClientCredentialsStorage
func (s *opStorage) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	s.logStub()
	return nil, nil
}

// op.TokenExchangeStorage
func (s *opStorage) ValidateTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) error {
	s.logStub()
	return nil
}

// op.TokenExchangeStorage
func (s *opStorage) CreateTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) error {
	s.logStub()
	return nil
}

// op.TokenExchangeStorage
func (s *opStorage) GetPrivateClaimsFromTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) (claims map[string]any, err error) {
	s.logStub()
	return nil, nil
}

// op.TokenExchangeStorage
func (s *opStorage) SetUserinfoFromTokenExchangeRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.TokenExchangeRequest) error {
	s.logStub()
	return nil
}

// op.TokenExchangeTokensVerifierStorage
func (s *opStorage) VerifyExchangeSubjectToken(ctx context.Context, token string, tokenType oidc.TokenType) (tokenIDOrToken string, subject string, tokenClaims map[string]any, err error) {
	s.logStub()
	return "", "", nil, nil
}

// op.TokenExchangeTokensVerifierStorage
func (s *opStorage) VerifyExchangeActorToken(ctx context.Context, token string, tokenType oidc.TokenType) (tokenIDOrToken string, actor string, tokenClaims map[string]any, err error) {
	s.logStub()
	return "", "", nil, nil
}

// op.OPStorage
func (s *opStorage) GetClientByClientID(_ context.Context, clientID string) (op.Client, error) {
	s.handler.mutex.RLock()
	defer s.handler.mutex.RUnlock()

	client := s.handler.clients[clientID]
	if client == nil {
		return nil, fmt.Errorf("unknown client id '%s'", clientID)
	}
	return client, nil
}

// op.OPStorage
func (s *opStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	s.logStub()
	return nil
}

// op.OPStorage
func (s *opStorage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	// SetUserinfoFromScopes is deprecated and should have an empty implementation for now.
	// Implement SetUserinfoFromRequest instead.
	s.logStub()
	return nil
}

// op.OPStorage
func (s *opStorage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	s.logStub()
	return nil
}

// op.OPStorage
func (s *opStorage) SetIntrospectionFromToken(ctx context.Context, userinfo *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	s.logStub()
	return nil
}

// op.OPStorage
func (s *opStorage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	s.logStub()
	return nil, nil
}

// op.OPStorage
func (s *opStorage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	s.logStub()
	return nil, nil
}

// op.OPStorage
func (s *opStorage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	s.logStub()
	return nil, nil
}

// op.JWTProfileTokenStorage
func (s *opStorage) JWTProfileTokenType(ctx context.Context, request op.TokenRequest) (op.AccessTokenType, error) {
	s.logStub()
	return 0, nil
}

// op.CanSetUserinfoFromRequest
func (s *opStorage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	s.logStub()
	return nil
}

// op.CanGetPrivateClaimsFromRequest
func (s *opStorage) GetPrivateClaimsFromRequest(ctx context.Context, request op.TokenRequest, restrictedScopes []string) (map[string]any, error) {
	s.logStub()
	return nil, nil
}

// op.Storage
func (s *opStorage) Health(context.Context) error {
	s.logStub()
	return nil
}

func (s *opStorage) logStub() {
	_, file, line, _ := runtime.Caller(1)
	s.handler.runtime.Logger().Warn("stub call", slog.String("location", fmt.Sprintf("%s:%d", file, line)))
}
