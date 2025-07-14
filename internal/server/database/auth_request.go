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
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type AuthRequest struct {
	ID            string
	ACR           string
	AMR           []string
	Audience      []string
	CreateTime    int64
	AuthTime      int64
	ClientID      string
	CodeChallenge *oidc.CodeChallenge
	Nonce         string
	RedirectURI   string
	ResponseType  oidc.ResponseType
	ResponseMode  oidc.ResponseMode
	Scopes        []string
	State         string
	Subject       string
	Done          bool
}

func NewAuthRequestFromOIDCAuthRequest(oidcAuthRequest *oidc.AuthRequest, userID string) *AuthRequest {
	var codeChallenge *oidc.CodeChallenge
	if oidcAuthRequest.CodeChallenge != "" {
		codeChallenge = &oidc.CodeChallenge{
			Challenge: oidcAuthRequest.CodeChallenge,
			Method:    oidcAuthRequest.CodeChallengeMethod,
		}
	}
	return &AuthRequest{
		ID:            uuid.NewString(),
		ACR:           "",
		AMR:           []string{"pwd"},
		Audience:      []string{oidcAuthRequest.ClientID},
		CreateTime:    time.Now().UnixMicro(),
		ClientID:      oidcAuthRequest.ClientID,
		CodeChallenge: codeChallenge,
		Nonce:         oidcAuthRequest.Nonce,
		RedirectURI:   oidcAuthRequest.RedirectURI,
		ResponseType:  oidcAuthRequest.ResponseType,
		ResponseMode:  oidcAuthRequest.ResponseMode,
		Scopes:        oidcAuthRequest.Scopes,
		State:         oidcAuthRequest.State,
		Subject:       userID,
		Done:          false,
	}
}

func (r *AuthRequest) OpAuthRequest() op.AuthRequest {
	return &OpAuthRequest{authRequest: *r}
}

type OpAuthRequest struct {
	authRequest AuthRequest
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
	return r.authRequest.RedirectURI
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
