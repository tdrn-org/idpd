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

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/internal/domain"
	"github.com/tdrn-org/idpd/internal/userstore"
)

// ─── Additional path constants (PathLogin is already in api.go) ─────

const PathSession = basePath + "/session"
const PathLogout = basePath + "/logout"
const PathLoginMFA = basePath + "/login/mfa"

// ─── Login Runtime interface ────────────────────────────────────────

// LoginRuntime extends Runtime with login-flow capabilities.
type LoginRuntime interface {
	Runtime

	// ── UserSessionRequest (login flow state) ──

	// CreateUserSessionRequest creates a new request for the given handler.
	CreateUserSessionRequest(ctx context.Context, handler string, strong bool) (*domain.UserSessionRequest, error)

	// GetUserSessionRequest retrieves a request by its public ID.
	GetUserSessionRequest(ctx context.Context, id string) (*domain.UserSessionRequest, error)

	// UpdateUserSessionRequest persists state changes.
	UpdateUserSessionRequest(ctx context.Context, request *domain.UserSessionRequest) error

	// ── Userstore ──

	// Users returns the configured userstore backend.
	Users() userstore.Backend
}

// ─── Session API ────────────────────────────────────────────────────

// SessionAPI adds session/login endpoints on top of the shared *API.
type SessionAPI struct {
	*API
	runtime LoginRuntime
}

func NewSessionAPI(base *API, runtime LoginRuntime) *SessionAPI {
	return &SessionAPI{
		API:     base,
		runtime: runtime,
	}
}

func (api *SessionAPI) Mount(server *httpserver.Instance) {
	server.HandleFunc("GET "+PathSession, api.SessionGet)
	server.HandleFunc("POST "+PathLogout, api.LogoutPost)
	server.HandleFunc("POST "+PathLogin, api.LoginPost)
	server.HandleFunc("POST "+PathLoginMFA, api.LoginMFAPost)
}

// ─── GET /api/v1/session ────────────────────────────────────────────

// SessionResponse carries the current session state.
type SessionResponse struct {
	Authenticated bool      `json:"authenticated"`
	User          *UserInfo `json:"user,omitempty"`
	// Strong indicates whether the current session satisfies strong requirements.
	Strong bool `json:"strong,omitempty"`
}

// UserInfo is a UI-safe subset of userstore data.
type UserInfo struct {
	Login      string   `json:"login"`
	Name       string   `json:"name"`
	GivenName  string   `json:"given_name"`
	FamilyName string   `json:"family_name"`
	Nickname   string   `json:"nickname"`
	Picture    string   `json:"picture"`
	Email      string   `json:"email"`
	Groups     []string `json:"groups"`
}

// GET @BasePath/session
//
//	@Summary		Get current session
//	@Description	Returns the active session's user info, or authenticated=false.
//	@Produce		json
//	@Success		200	{object}	SessionResponse
//	@Router			/api/v1/session [get]
func (api *SessionAPI) SessionGet(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement session lookup via cookie/header.
	// For now, return unauthenticated.
	api.sendApplicationJSONResponse(w, r, http.StatusOK, &SessionResponse{
		Authenticated: false,
	})
}

// ─── POST /api/v1/logout ────────────────────────────────────────────

// POST @BasePath/logout
//
//	@Summary		End current session
//	@Description	Terminates the active session and clears the session cookie.
//	@Produce		json
//	@Success		200	{object}	map[string]any
//	@Router			/api/v1/logout [post]
func (api *SessionAPI) LogoutPost(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement session termination.
	api.sendApplicationJSONResponse(w, r, http.StatusOK, map[string]any{"ok": true})
}

// ─── POST /api/v1/login ─────────────────────────────────────────────

// LoginRequest is the credentials submission payload.
type LoginRequest struct {
	// ID is the UserSessionRequest's public ID (from the login GET redirect).
	ID string `json:"id"`
	// Login is the username.
	Login string `json:"login"`
	// Password is the user's password.
	Password string `json:"password"`
	// Remember requests a persistent session.
	Remember bool `json:"remember"`
}

// LoginResponse is always returned after credentials are processed.
//
//	No-Leak principle: the response is identical whether credentials
//	were valid or not. Failure is only revealed after MFA completes.
type LoginResponse struct {
	// Next is always "mfa" — the next step in the flow.
	Next string `json:"next"`
	// Redirect is the URL the UI should navigate to.
	Redirect string `json:"redirect"`
}

// POST @BasePath/login
//
//	@Summary		Submit login credentials
//	@Description	Validates credentials via userstore. Always returns MFA redirect
//	@Description	(No-Leak: response is identical for valid and invalid credentials).
//	@Accept			json
//	@Produce		json
//	@Param			body	body	LoginRequest	true	"Credentials"
//	@Success		200		{object}	LoginResponse
//	@Router			/api/v1/login [post]
func (api *SessionAPI) LoginPost(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, r, http.StatusBadRequest, err)
		return
	}

	// Retrieve the flow state created by LoginGet.
	request, err := api.runtime.GetUserSessionRequest(r.Context(), req.ID)
	if err != nil {
		api.sendError(w, r, http.StatusInternalServerError, err)
		return
	}

	// Authenticate. The result is stored in AuthInfo but never
	// revealed in the response — No-Leak.
	err = api.runtime.Users().AuthenticateUser(r.Context(), req.Login, req.Password)
	request.AuthInfo.Login = req.Login
	request.AuthInfo.Remember = req.Remember
	if err != nil {
		// TODO: Mark request as tainted (auth failed).
		// The MFA step will surface the combined result.
	}
	if err := api.runtime.UpdateUserSessionRequest(r.Context(), request); err != nil {
		api.sendError(w, r, http.StatusInternalServerError, err)
		return
	}

	// Always return MFA redirect.
	api.sendApplicationJSONResponse(w, r, http.StatusOK, &LoginResponse{
		Next:     "mfa",
		Redirect: PathLoginMFA + "?id=" + req.ID,
	})
}

// ─── POST /api/v1/login/mfa ─────────────────────────────────────────

// MFARequest is the MFA verification payload.
type MFARequest struct {
	// ID is the UserSessionRequest's public ID.
	ID string `json:"id"`
	// Method is the verification method: "totp", "email", or "passkey".
	Method string `json:"method"`
	// Code is the verification code.
	Code string `json:"code"`
}

// MFAResponse is returned after MFA verification.
type MFAResponse struct {
	// OK is true when MFA succeeded AND credentials were valid.
	OK bool `json:"ok"`
	// Redirect is set on success — navigate here to continue the flow.
	Redirect string `json:"redirect,omitempty"`
	// Error describes the failure reason (for UI display).
	Error string `json:"error,omitempty"`
}

// POST @BasePath/login/mfa
//
//	@Summary		Verify MFA
//	@Description	Verifies the MFA code. If the login was tainted, this also fails.
//	@Accept			json
//	@Produce		json
//	@Param			body	body	MFARequest	true	"MFA verification"
//	@Success		200		{object}	MFAResponse
//	@Router			/api/v1/login/mfa [post]
func (api *SessionAPI) LoginMFAPost(w http.ResponseWriter, r *http.Request) {
	var req MFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, r, http.StatusBadRequest, err)
		return
	}

	request, err := api.runtime.GetUserSessionRequest(r.Context(), req.ID)
	if err != nil {
		api.sendError(w, r, http.StatusInternalServerError, err)
		return
	}
	if request == nil {
		api.sendApplicationJSONResponse(w, r, http.StatusOK, &MFAResponse{
			OK:    false,
			Error: "session_expired",
		})
		return
	}

	// TODO: If tainted (bad credentials), fail here — revealing the
	// combined result. The MFA attempt still "runs" to prevent timing leaks.
	// if request.AuthInfo.Tainted { ... }

	verification := domain.Verification(req.Method)
	request.AuthInfo.Verification = verification

	// TODO: Verify the MFA code against the stored challenge.
	// For now, accept any code and mark as identified.

	request.AuthInfo.State = domain.UserSessionRequestStateIdentified

	if err := api.runtime.UpdateUserSessionRequest(r.Context(), request); err != nil {
		api.sendError(w, r, http.StatusInternalServerError, err)
		return
	}

	// Redirect back to the handler that initiated this flow.
	api.sendApplicationJSONResponse(w, r, http.StatusOK, &MFAResponse{
		OK:       true,
		Redirect: "/api/v1/login?handler=" + request.AuthInfo.Handler + "&id=" + req.ID,
	})
}
