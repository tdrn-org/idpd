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

package database

import (
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type OAuth2Token struct {
	ID             string
	ClientID       string
	Subject        string
	RefreshTokenID string
	Audience       []string
	Expiration     int64
	Scopes         []string
}

func NewOAuth2Token(id string) *OAuth2Token {
	return &OAuth2Token{
		ID:       id,
		Audience: []string{},
		Scopes:   []string{},
	}
}

func NewOAuth2TokenFromAuthRequest(request op.AuthRequest, refreshTokenID string) *OAuth2Token {
	return &OAuth2Token{
		ID:             uuid.NewString(),
		ClientID:       request.GetClientID(),
		Subject:        request.GetSubject(),
		RefreshTokenID: refreshTokenID,
		Audience:       request.GetAudience(),
		Expiration:     time.Now().Add(5 * time.Minute).UnixMicro(),
		Scopes:         request.GetScopes(),
	}
}

func NewOAuth2TokenFromTokenExchangeRequest(request op.TokenExchangeRequest, refreshTokenID string) *OAuth2Token {
	return &OAuth2Token{
		ID:             uuid.NewString(),
		ClientID:       request.GetClientID(),
		Subject:        request.GetSubject(),
		RefreshTokenID: refreshTokenID,
		Audience:       request.GetAudience(),
		Expiration:     time.Now().Add(5 * time.Minute).UnixMicro(),
		Scopes:         request.GetScopes(),
	}
}

type OAuth2RefreshToken struct {
	ID            string
	AuthTime      int64
	AMR           []string
	Audience      []string
	Subject       string
	ClientID      string
	Expiration    int64
	Scopes        []string
	AccessTokenID string
}

func NewOAuth2RefreshTokenID() string {
	return uuid.NewString()
}

func NewOAuth2RefreshToken(id string) *OAuth2RefreshToken {
	return &OAuth2RefreshToken{
		ID:       id,
		AMR:      []string{},
		Audience: []string{},
		Scopes:   []string{},
	}
}

func NewOAuth2RefreshTokenFromAuthRequest(id string, tokenID string, request op.AuthRequest) *OAuth2RefreshToken {
	return &OAuth2RefreshToken{
		ID:            id,
		AuthTime:      request.GetAuthTime().UnixMicro(),
		AMR:           request.GetAMR(),
		Audience:      request.GetAudience(),
		Subject:       request.GetSubject(),
		ClientID:      request.GetClientID(),
		Expiration:    time.Now().Add(5 * time.Minute).UnixMicro(),
		Scopes:        request.GetScopes(),
		AccessTokenID: tokenID,
	}
}

func NewOAuth2RefreshTokenFromRefreshToken(id string, tokenID string, refreshToken *OAuth2RefreshToken) *OAuth2RefreshToken {
	return &OAuth2RefreshToken{
		ID:            id,
		AuthTime:      refreshToken.AuthTime,
		AMR:           refreshToken.AMR,
		Audience:      refreshToken.Audience,
		Subject:       refreshToken.Subject,
		ClientID:      refreshToken.ClientID,
		Expiration:    time.Now().Add(5 * time.Minute).UnixMicro(),
		Scopes:        refreshToken.Scopes,
		AccessTokenID: tokenID,
	}
}

func (t *OAuth2RefreshToken) OpRefreshToken() op.RefreshTokenRequest {
	return &OpRefreshTokenRequest{refreshToken: *t}
}

type OpRefreshTokenRequest struct {
	refreshToken OAuth2RefreshToken
}

func (r *OpRefreshTokenRequest) GetAMR() []string {
	return r.refreshToken.AMR
}

func (r *OpRefreshTokenRequest) GetAudience() []string {
	return r.refreshToken.Audience
}

func (r *OpRefreshTokenRequest) GetAuthTime() time.Time {
	return time.UnixMicro(r.refreshToken.AuthTime)
}

func (r *OpRefreshTokenRequest) GetClientID() string {
	return r.refreshToken.ClientID
}

func (r *OpRefreshTokenRequest) GetScopes() []string {
	return r.refreshToken.Scopes
}

func (r *OpRefreshTokenRequest) GetSubject() string {
	return r.refreshToken.Subject
}

func (r *OpRefreshTokenRequest) SetCurrentScopes(scopes []string) {
	r.refreshToken.Scopes = scopes
}
