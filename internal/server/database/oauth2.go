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
	serverconf "github.com/tdrn-org/idpd/internal/server/conf"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type OAuth2AuthRequest struct {
	ID            string
	ACR           string
	AMR           []string
	Audience      []string
	Expiration    int64
	AuthTime      int64
	ClientID      string
	CodeChallenge *oidc.CodeChallenge
	Nonce         string
	RedirectURL   string
	ResponseType  oidc.ResponseType
	ResponseMode  oidc.ResponseMode
	Scopes        []string
	State         string
	Subject       string
	Challenge     string
	Remember      bool
	Done          bool
}

func NewOAuth2AuthRequest(id string) *OAuth2AuthRequest {
	return &OAuth2AuthRequest{
		ID:       id,
		AMR:      []string{},
		Audience: []string{},
		Scopes:   []string{},
	}
}

func NewOAuth2AuthRequestFromOIDCAuthRequest(oidcAuthRequest *oidc.AuthRequest, userID string) *OAuth2AuthRequest {
	var codeChallenge *oidc.CodeChallenge
	if oidcAuthRequest.CodeChallenge != "" {
		codeChallenge = &oidc.CodeChallenge{
			Challenge: oidcAuthRequest.CodeChallenge,
			Method:    oidcAuthRequest.CodeChallengeMethod,
		}
	}
	return &OAuth2AuthRequest{
		ID:            uuid.NewString(),
		ACR:           "",
		AMR:           []string{"pwd"},
		Audience:      []string{oidcAuthRequest.ClientID},
		Expiration:    time.Now().Add(serverconf.LookupRuntime().RequestLifetime).UnixMicro(),
		ClientID:      oidcAuthRequest.ClientID,
		CodeChallenge: codeChallenge,
		Nonce:         oidcAuthRequest.Nonce,
		RedirectURL:   oidcAuthRequest.RedirectURI,
		ResponseType:  oidcAuthRequest.ResponseType,
		ResponseMode:  oidcAuthRequest.ResponseMode,
		Scopes:        oidcAuthRequest.Scopes,
		State:         oidcAuthRequest.State,
		Subject:       userID,
		Done:          false,
	}
}

func (r *OAuth2AuthRequest) Expired() bool {
	return r.Expiration < time.Now().UnixMicro()
}

func (r *OAuth2AuthRequest) OpAuthRequest() op.AuthRequest {
	return &OpAuthRequest{authRequest: *r}
}

type OpAuthRequest struct {
	authRequest OAuth2AuthRequest
}

func (r *OpAuthRequest) GetID() string {
	return r.authRequest.ID
}

func (r *OpAuthRequest) GetACR() string {
	return r.authRequest.ACR
}

func (r *OpAuthRequest) GetAMR() []string {
	return r.authRequest.AMR
}

func (r *OpAuthRequest) GetAudience() []string {
	return r.authRequest.Audience
}

func (r *OpAuthRequest) GetAuthTime() time.Time {
	return time.UnixMicro(r.authRequest.AuthTime)
}

func (r *OpAuthRequest) GetClientID() string {
	return r.authRequest.ClientID
}

func (r *OpAuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return r.authRequest.CodeChallenge
}

func (r *OpAuthRequest) GetNonce() string {
	return r.authRequest.Nonce
}

func (r *OpAuthRequest) GetRedirectURI() string {
	return r.authRequest.RedirectURL
}

func (r *OpAuthRequest) GetResponseType() oidc.ResponseType {
	return r.authRequest.ResponseType
}

func (r *OpAuthRequest) GetResponseMode() oidc.ResponseMode {
	return r.authRequest.ResponseMode
}

func (r *OpAuthRequest) GetScopes() []string {
	return r.authRequest.Scopes
}

func (r *OpAuthRequest) GetState() string {
	return r.authRequest.State
}

func (r *OpAuthRequest) GetSubject() string {
	return r.authRequest.Subject
}

func (r *OpAuthRequest) Done() bool {
	return r.authRequest.Done
}

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
		Expiration:     time.Now().Add(serverconf.LookupRuntime().RequestLifetime).UnixMicro(),
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
		Expiration:     time.Now().Add(serverconf.LookupRuntime().TokenLifetime).UnixMicro(),
		Scopes:         request.GetScopes(),
	}
}

func NewOAuth2TokenFromRefreshTokenRequest(request op.RefreshTokenRequest, refreshTokenID string) *OAuth2Token {
	return &OAuth2Token{
		ID:             uuid.NewString(),
		ClientID:       request.GetClientID(),
		Subject:        request.GetSubject(),
		RefreshTokenID: refreshTokenID,
		Audience:       request.GetAudience(),
		Expiration:     time.Now().Add(serverconf.LookupRuntime().TokenLifetime).UnixMicro(),
		Scopes:         request.GetScopes(),
	}
}

func (t *OAuth2Token) Expired() bool {
	return t.Expiration < time.Now().UnixMicro()
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
		Expiration:    time.Now().Add(serverconf.LookupRuntime().TokenLifetime).UnixMicro(),
		Scopes:        request.GetScopes(),
		AccessTokenID: tokenID,
	}
}

func NewOAuth2RefreshTokenFromTokenExchangeRequest(id string, tokenID string, request op.TokenExchangeRequest) *OAuth2RefreshToken {
	return &OAuth2RefreshToken{
		ID:            id,
		AuthTime:      request.GetAuthTime().UnixMicro(),
		AMR:           request.GetAMR(),
		Audience:      request.GetAudience(),
		Subject:       request.GetSubject(),
		ClientID:      request.GetClientID(),
		Expiration:    time.Now().Add(serverconf.LookupRuntime().TokenLifetime).UnixMicro(),
		Scopes:        request.GetScopes(),
		AccessTokenID: tokenID,
	}
}

func NewOAuth2RefreshTokenFromRefreshTokenRequest(id string, tokenID string, request op.RefreshTokenRequest) *OAuth2RefreshToken {
	return &OAuth2RefreshToken{
		ID:            id,
		AuthTime:      request.GetAuthTime().UnixMicro(),
		AMR:           request.GetAMR(),
		Audience:      request.GetAudience(),
		Subject:       request.GetSubject(),
		ClientID:      request.GetClientID(),
		Expiration:    time.Now().Add(serverconf.LookupRuntime().TokenLifetime).UnixMicro(),
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
		Expiration:    time.Now().Add(serverconf.LookupRuntime().TokenLifetime).UnixMicro(),
		Scopes:        refreshToken.Scopes,
		AccessTokenID: tokenID,
	}
}

func (t *OAuth2RefreshToken) Expired() bool {
	return t.Expiration < time.Now().UnixMicro()
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
