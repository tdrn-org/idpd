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

package rest

import "github.com/tdrn-org/idpd/internal/domain"

type StatusCode string

const (
	StatusCodeNoSession                StatusCode = "no_session"
	StatusCodeAuthRequestNotAccessible StatusCode = "auth_request_not_accessible"
)

type StatusResponse struct {
	Success bool       `json:"success"`
	Status  int        `json:"status"`
	Code    StatusCode `json:"code,omitempty"`
}

type ExtendedStatusResponse[T any] struct {
	Success bool       `json:"success"`
	Status  int        `json:"status"`
	Code    StatusCode `json:"code,omitempty"`
	Data    *T         `json:"data,omitempty"`
}

type ServerInfo struct {
	// The server version
	Version string `json:"version"`
	// The server's base URL
	BaseURL string `json:"base_url"`
}

type ServerInfoResponse ExtendedStatusResponse[ServerInfo]

type SessionInfo struct {
	StrongAuth bool     `json:"strong_auth"`
	User       UserInfo `json:"user"`
}

type UserInfo struct {
	Login    string   `json:"login"`
	Name     string   `json:"name"`
	Nickname string   `json:"nickname"`
	Picture  string   `json:"picture"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
}

type SessionInfoResponse ExtendedStatusResponse[SessionInfo]

type SessionLoginInfo struct {
	// LoginHint contains a hint for the login to use, if any can be derived from context.
	// Can be overriden by the user.
	LoginHint string `json:"login_hint"`
	// Remember indicates the default for whether to remember the login across browser sessions or not.
	// Can be overriden by the user.
	Remember bool `json:"remember"`
	// AllowedVerifications lists the allowed verification methods for this login flow.
	// Only verification methods from this list are accepted during this login flow.
	AllowedVerifications []domain.Verification `json:"allowed_verifications"`
}

type SessionLoginInfoResponse ExtendedStatusResponse[SessionLoginInfo]

type SessionLoginRequest struct {
	// Login is the user login to use for the authentication
	Login string `json:"login"`
	// Remember indicates whether to remember the given login across browser sessions or not.
	Remember bool `json:"remember"`
	// Password is the user password to use for the authentication
	Password string `json:"password"`
	// Verification is the verification method to perform in the next step auf the authentication flow.
	Verification domain.Verification `json:"verification"`
}
