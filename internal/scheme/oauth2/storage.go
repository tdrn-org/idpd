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
	return s.handler.createAuthRequest(ctx, oidcAuthRequest, idTokenHintUserID)
}

// op.AuthStorage
func (s *opStorage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return s.handler.getAuthRequest(ctx, id)
}

// op.AuthStorage
func (s *opStorage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	return s.handler.getAuthRequestByCode(ctx, code)
}

// op.AuthStorage
func (s *opStorage) SaveAuthCode(ctx context.Context, id string, code string) error {
	return s.handler.runtime.DataStore().Atomic(ctx, func(txCtx context.Context, tx *database.Tx) error {
		_, err := model.InsertAuthCode(txCtx, tx, code, id)
		return err
	})
}

// op.AuthStorage
func (s *opStorage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.handler.runtime.DataStore().Atomic(ctx, func(txCtx context.Context, tx *database.Tx) error {
		err := model.DeleteAuthCodeByAuthRequestID(txCtx, tx, id)
		if err != nil {
			return err
		}
		return model.DeleteAuthRequestByID(txCtx, tx, id)
	})
}

// op.AuthStorage
func (s *opStorage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	var tokenID string
	var tokenExpiryTime time.Time
	var err error
	switch request := request.(type) {
	case *opAuthRequest:
		tokenID, tokenExpiryTime, err = s.handler.createTokenFromAuthRequest(ctx, request, "")
	case op.TokenExchangeRequest:
		s.logStub()
	case *oidc.JWTTokenRequest:
		s.logStub()
	default:
		err = fmt.Errorf("unexpected access token request type: %T", request)
	}
	return tokenID, tokenExpiryTime, err
}

// op.AuthStorage
func (s *opStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	var tokenID string
	var refreshTokenID string
	var tokenExpiryTime time.Time
	var err error
	switch request := request.(type) {
	case *opAuthRequest:
		s.logStub()
	case op.TokenExchangeRequest:
		s.logStub()
	case op.RefreshTokenRequest:
		s.logStub()
	default:
		err = fmt.Errorf("unexpected access and refresh token request type: %T", request)
	}
	return tokenID, refreshTokenID, tokenExpiryTime, err
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
	signingKey, err := s.handler.activeSigningKey(ctx, jose.SignatureAlgorithm(s.handler.cfg.SigningKeyAlgorithm))
	if err != nil {
		return nil, err
	}
	return &opSigningKey{signingKey: signingKey}, nil
}

// op.AuthStorage
func (s *opStorage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	signingKey, err := s.handler.activeSigningKey(ctx, jose.SignatureAlgorithm(s.handler.cfg.SigningKeyAlgorithm))
	if err != nil {
		return nil, err
	}
	return []jose.SignatureAlgorithm{signingKey.Algorithm}, nil
}

// op.AuthStorage
func (s *opStorage) KeySet(ctx context.Context) ([]op.Key, error) {
	signingKey, err := s.handler.activeSigningKey(ctx, jose.SignatureAlgorithm(s.handler.cfg.SigningKeyAlgorithm))
	if err != nil {
		return nil, err
	}
	return []op.Key{&opKey{signingKey: signingKey}}, nil
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
		return nil, fmt.Errorf("%w;client id '%s'", ErrUnknownClient, clientID)
	}
	return client, nil
}

// op.OPStorage
func (s *opStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	s.handler.mutex.RLock()
	defer s.handler.mutex.RUnlock()

	client := s.handler.clients[clientID]
	if client == nil {
		return fmt.Errorf("%w;client id '%s'", ErrUnknownClient, clientID)
	}
	if client.cfg.Secret != clientSecret {
		return ErrInvalidClientSecret
	}
	return nil
}

// op.OPStorage
func (s *opStorage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	// SetUserinfoFromScopes is deprecated and should have an empty implementation for now.
	// Implement SetUserinfoFromRequest instead.
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
	return s.handler.populateUserinfo(ctx, userinfo, request.GetSubject(), scopes)
}

// op.CanGetPrivateClaimsFromRequest
func (s *opStorage) GetPrivateClaimsFromRequest(ctx context.Context, request op.TokenRequest, restrictedScopes []string) (map[string]any, error) {
	s.logStub()
	return nil, nil
}

// op.Storage
func (s *opStorage) Health(_ context.Context) error {
	return nil
}

func (s *opStorage) logStub() {
	_, file, line, _ := runtime.Caller(1)
	s.handler.runtime.Logger().Warn("stub call", slog.String("location", fmt.Sprintf("%s:%d", file, line)))
}
