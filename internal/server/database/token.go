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

type Token struct {
	ID             string
	ApplicationID  string
	Subject        string
	RefreshTokenID string
	Audience       []string
	Expiration     int64
	Scopes         []string
}

func NewTokenFromAuthRequest(request op.AuthRequest, refreshTokenID string) *Token {
	return &Token{
		ID:             uuid.NewString(),
		ApplicationID:  request.GetClientID(),
		Subject:        request.GetSubject(),
		RefreshTokenID: refreshTokenID,
		Audience:       request.GetAudience(),
		Expiration:     time.Now().Add(5 * time.Minute).UnixMicro(),
		Scopes:         request.GetScopes(),
	}
}

func NewTokenFromTokenExchangeRequest(request op.TokenExchangeRequest, refreshTokenID string) *Token {
	return &Token{
		ID:             uuid.NewString(),
		ApplicationID:  request.GetClientID(),
		Subject:        request.GetSubject(),
		RefreshTokenID: refreshTokenID,
		Audience:       request.GetAudience(),
		Expiration:     time.Now().Add(5 * time.Minute).UnixMicro(),
		Scopes:         request.GetScopes(),
	}
}

type RefreshToken struct {
	ID            string
	AuthTime      int64
	AMR           []string
	Audience      []string
	UserID        string
	ApplicationID string
	Expiration    int64
	Scopes        []string
	AccessTokenID string
}

func NewRefreshTokenID() string {
	return uuid.NewString()
}

func NewRefreshTokenFromAuthRequest(id string, tokenID string, request op.AuthRequest) *RefreshToken {
	return &RefreshToken{
		ID:            id,
		AuthTime:      request.GetAuthTime().UnixMicro(),
		AMR:           request.GetAMR(),
		Audience:      request.GetAudience(),
		UserID:        request.GetSubject(),
		ApplicationID: request.GetClientID(),
		Expiration:    time.Now().Add(5 * time.Minute).UnixMicro(),
		Scopes:        request.GetScopes(),
		AccessTokenID: tokenID,
	}
}

func NewRefreshTokenFromRefreshToken(id string, tokenID string, refreshToken *RefreshToken) *RefreshToken {
	return &RefreshToken{
		ID:            id,
		AuthTime:      refreshToken.AuthTime,
		AMR:           refreshToken.AMR,
		Audience:      refreshToken.Audience,
		UserID:        refreshToken.UserID,
		ApplicationID: refreshToken.ApplicationID,
		Expiration:    time.Now().Add(5 * time.Minute).UnixMicro(),
		Scopes:        refreshToken.Scopes,
		AccessTokenID: tokenID,
	}
}
