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
	"golang.org/x/oauth2"
)

type UserSessionRequest struct {
	ID         string
	State      string
	CreateTime int64
	Remember   bool
}

func NewUserSessionRequest(state string, remember bool) *UserSessionRequest {
	return &UserSessionRequest{
		ID:         uuid.NewString(),
		State:      state,
		CreateTime: time.Now().UnixMicro(),
		Remember:   remember,
	}
}

type UserSession struct {
	ID           string
	Remember     bool
	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiration   int64
}

func NewUserSession(token *oauth2.Token, remember bool) *UserSession {
	return &UserSession{
		ID:           uuid.NewString(),
		Remember:     remember,
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiration:   token.Expiry.UnixMicro(),
	}
}

func (session *UserSession) OAuth2Token() *oauth2.Token {
	expiresIn := session.Expiration - time.Now().UnixMicro()
	if expiresIn < 0 {
		expiresIn = 0
	}
	return &oauth2.Token{
		AccessToken:  session.AccessToken,
		TokenType:    session.TokenType,
		RefreshToken: session.RefreshToken,
		Expiry:       time.UnixMicro(session.Expiration),
		ExpiresIn:    expiresIn,
	}
}
