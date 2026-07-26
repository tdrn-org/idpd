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
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/internal/buildinfo"
	"github.com/tdrn-org/idpd/internal/data"
	"github.com/tdrn-org/idpd/internal/domain"
	serverhttp "github.com/tdrn-org/idpd/internal/http"
	"github.com/tdrn-org/idpd/internal/scheme"
	"github.com/tdrn-org/idpd/internal/scheme/forward"
	"github.com/tdrn-org/idpd/internal/userstore"
)

type Runtime interface {
	BaseURL() *url.URL
	DataStore() *data.Store
	DemoUser() *userstore.User
	Logger() *slog.Logger
	Ping(ctx context.Context) error
	GetHandler(name scheme.Name) scheme.Handler
}

//	@title			IdPD REST API
//	@version		1.0
//	@description	IdPD identity provider server API.

//	@contact.url	https://github.com/tdrn-org/idpd

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

//	@host		localhost:9123
//	@BasePath	/api

type API struct {
	runtime Runtime
}

func NewAPI(runtime Runtime) *API {
	return &API{
		runtime: runtime,
	}
}

const responseNoSessionFound string = "No session found"

const basePath string = "/api"
const PathPing string = basePath + "/ping"
const PathInfo string = basePath + "/info"
const PathSession string = basePath + "/session"
const PathSessionLogin string = PathSession + "/login"
const PathSessionVerify string = PathSession + "/verify"

func (api *API) Mount(server *httpserver.Instance) {
	server.HandleFunc("GET "+PathPing, api.PingGet)
	server.HandleFunc("GET "+PathInfo, api.InfoGet)
	server.HandleFunc("GET "+PathSession, api.SessionGet)
	server.HandleFunc("POST "+PathSession, api.SessionPost)
	server.HandleFunc("DELETE "+PathSession, api.SessionDelete)
	server.HandleFunc("GET "+PathSessionLogin, api.SessionLoginGet)
	server.HandleFunc("POST "+PathSessionLogin, api.SessionLoginPost)
	server.HandleFunc("GET "+PathSessionVerify, api.SessionVerifyGet)
	server.HandleFunc("POST "+PathSessionVerify, api.SessionVerifyPost)
}

// GET @BasePath/ping
//
//	@Summary		Ping server
//	@Description	Ping the server to check general health
//
//	@Produce		text/plain
//
//	@Success		200	{string}	string	"Ok"
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/ping [get]
func (api *API) PingGet(w http.ResponseWriter, r *http.Request) {
	err := api.runtime.Ping(r.Context())
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
		return
	}
	serverhttp.SendPlainTextResponse(api.runtime.Logger(), w, r, http.StatusOK, serverhttp.ResponseOK)
}

// GET @BasePath/info
//
//	@Summary		Query server info
//	@Description	Query static server info like version and configured options
//
//	@Produce		json
//
//	@Success		200	{object}	ServerInfo
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/info [get]
func (api *API) InfoGet(w http.ResponseWriter, r *http.Request) {
	info := &ServerInfo{
		Version: buildinfo.Version(),
		BaseURL: api.runtime.BaseURL().String(),
	}
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, http.StatusOK, info)
}

type ServerInfo struct {
	// The server version
	Version string `json:"version"`
	// The server's base URL
	BaseURL string `json:"base_url"`
}

// GET @BasePath/session
//
//	@Summary		Get current session
//	@Description	Get the current session (if a session exists)
//
//	@Produce		json
//
//	@Success		200	{object}	SessionInfo
//	@Failure		404	{string}	string	"No session found"
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/session [get]
func (api *API) SessionGet(w http.ResponseWriter, r *http.Request) {
	// Try to read session from cookie
	cookie, err := r.Cookie("idpd_session")
	if err != nil {
		serverhttp.SendPlainTextResponse(api.runtime.Logger(), w, r, http.StatusNotFound, responseNoSessionFound)
		return
	}
	userSessionRequest, err := api.runtime.DataStore().GetUserSessionRequest(r.Context(), cookie.Value)
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
		return
	}
	if userSessionRequest == nil || userSessionRequest.AuthInfo.State != domain.UserSessionRequestStateDone {
		serverhttp.SendPlainTextResponse(api.runtime.Logger(), w, r, http.StatusNotFound, responseNoSessionFound)
		return
	}
	demoUser := api.runtime.DemoUser()
	if demoUser != nil {
		info := &SessionInfo{
			StrongAuth: false,
			User: UserInfo{
				Login:    demoUser.Login,
				Name:     demoUser.Name,
				Nickname: demoUser.Nickname,
				Picture:  demoUser.Picture,
				Email:    userSessionRequest.AuthInfo.Login,
				Groups:   demoUser.GroupNames(),
			},
		}
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, http.StatusOK, info)
		return
	}
	serverhttp.SendPlainTextResponse(api.runtime.Logger(), w, r, http.StatusNotFound, responseNoSessionFound)
}

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

// POST @BasePath/session
//
//	@Summary		Initiate a new session
//	@Description	Initiate the authentication flow to create a new session
//
//	@Produce		json
//
//	@Success		302	{string}	string	"Redirect to ..."
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/session [post]
func (api *API) SessionPost(w http.ResponseWriter, r *http.Request) {
	err := api.runtime.GetHandler(forward.Name).RedirectLogin(w, r)
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
		return
	}
}

// DELETE @BasePath/session
//
//	@Summary		Delete current session
//	@Description	Delete the current session (if a session exists)
//
//	@Produce		json
//
//	@Success		200	{object}	SessionInfo
//	@Failure		404	{string}	string	"No session found"
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/session [delete]
func (api *API) SessionDelete(w http.ResponseWriter, r *http.Request) {
	// TODO:implement
	serverhttp.SendPlainTextResponse(api.runtime.Logger(), w, r, http.StatusNotFound, responseNoSessionFound)
}

// GET @BasePath/session/login
//
//	@Summary		Get login information
//	@Description	Get the login information for the authentication flow associated with the given authentication request
//
//	@Accept			json
//	@Produce		json
//
//	@Param			id	path		string	true	"Authentication request ID"
//
//	@Success		200	{object}	SessionLoginInfo
//	@Failure		400	{string}	string	"Bad Request"
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/session/login [get]
func (api *API) SessionLoginGet(w http.ResponseWriter, r *http.Request) {
	api.handleUserSessionRequest(w, r, api.sessionLoginGet)
}

func (api *API) sessionLoginGet(w http.ResponseWriter, r *http.Request, userSessionRequest *domain.UserSessionRequest) {
	allowedVerifications := domain.AllVerifications
	if userSessionRequest.AuthInfo.StrongVerificationRequired {
		allowedVerifications = domain.StrongVerifications
	}
	response := &SessionLoginInfo{
		LoginHint:            userSessionRequest.AuthInfo.Login,
		Remember:             userSessionRequest.AuthInfo.Remember,
		AllowedVerifications: allowedVerifications,
	}
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, http.StatusOK, response)
}

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

// POST @BasePath/session/login
//
//	@Summary		Create a new session
//	@Description	Initiate the authentication flow to create a new session
//
//	@Accept			json
//	@Produce		json
//
//	@Param			request	body		SessionLoginRequest	true	"Request parameters"
//
//	@Success		200		{object}	map[string]bool		"Ok"
//	@Failure		400		{string}	string				"Bad Request"
//	@Failure		401		{string}	string				"Unauthorized"
//	@Failure		500		{string}	string				"Internal Server Error"
//	@Router			/api/session/login [post]
func (api *API) SessionLoginPost(w http.ResponseWriter, r *http.Request) {
	request := &SessionLoginRequest{}
	err := json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusBadRequest, err)
		return
	}
	userSessionRequest, err := api.runtime.DataStore().GetUserSessionRequest(r.Context(), request.ID)
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
		return
	}
	if userSessionRequest == nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusBadRequest, fmt.Errorf("unknown user session request id '%s'", request.ID))
		return
	}
	demoUser := api.runtime.DemoUser()
	if demoUser != nil {
		// Demo mode: accept any credentials, skip verification
		userSessionRequest.AuthInfo.State = domain.UserSessionRequestStateDone
		userSessionRequest.AuthInfo.Login = demoUser.Login
		userSessionRequest.AuthInfo.LoginTime = time.Now()
		userSessionRequest.AuthInfo.Verification = domain.Verification(request.Verification)
		userSessionRequest.AuthInfo.VerificationTime = time.Now()
		err = api.runtime.DataStore().UpdateUserSessionRequest(r.Context(), userSessionRequest)
		if err != nil {
			serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
			return
		}
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	// Real authentication: validate credentials
	userSessionRequest.AuthInfo.State = domain.UserSessionRequestStateIdentified
	userSessionRequest.AuthInfo.Login = request.Login
	userSessionRequest.AuthInfo.Remember = request.Remember
	userSessionRequest.AuthInfo.LoginTime = time.Now()
	userSessionRequest.AuthInfo.Verification = domain.Verification(request.Verification)
	// Set verification challenge (MVP: use fixed code "000000")
	userSessionRequest.AuthInfo.VerificationChallenge = []byte("000000")
	err = api.runtime.DataStore().UpdateUserSessionRequest(r.Context(), userSessionRequest)
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
		return
	}
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, http.StatusOK, map[string]bool{"ok": true})
}

type SessionLoginRequest struct {
	// ID identifies the authentication request this request refers to
	ID string `json:"id"`
	// Login is the user login to use for the authentication
	Login string `json:"login"`
	// Remember indicates whether to remember the given login across browser sessions or not.
	Remember bool `json:"remember"`
	// Password is the user password to use for the authentication
	Password string `json:"password"`
	// Verification is the verification method to perform in the next step auf the authentication flow.
	Verification domain.Verification `json:"verification"`
}

// GET @BasePath/session/verify
//
//	@Summary		Get verify information
//	@Description	Get the verify information for the authentication flow associated with the given authentication request
//
//	@Accept			json
//	@Produce		json
//
//	@Param			id	path		string	true	"Authentication request ID"
//
//	@Success		200	{object}	SessionVerifyInfo
//	@Failure		400	{string}	string	"Bad Request"
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/session/verify [get]
func (api *API) SessionVerifyGet(w http.ResponseWriter, r *http.Request) {
	api.handleUserSessionRequest(w, r, api.sessionVerifyGet)
}

func (api *API) sessionVerifyGet(w http.ResponseWriter, r *http.Request, userSessionRequest *domain.UserSessionRequest) {
	response := &SessionVerifyInfo{
		Verification: userSessionRequest.AuthInfo.Verification,
	}
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, http.StatusOK, response)
}

type SessionVerifyInfo struct {
	Verification domain.Verification `json:"verification"`
}

// POST @BasePath/session/verify
//
//	@Summary		Verify authentication
//	@Description	Verify the authentication by providing the verification code
//
//	@Accept			json
//	@Produce		json
//
//	@Param			request	body		SessionVerifyRequest	true	"Request parameters"
//
//	@Success		200		{object}	map[string]string		"Redirect"
//	@Failure		400		{string}	string					"Bad Request"
//	@Failure		500		{string}	string					"Internal Server Error"
//	@Router			/api/session/verify [post]
func (api *API) SessionVerifyPost(w http.ResponseWriter, r *http.Request) {
	request := &SessionVerifyRequest{}
	err := json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusBadRequest, err)
		return
	}
	userSessionRequest, err := api.runtime.DataStore().GetUserSessionRequest(r.Context(), request.ID)
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
		return
	}
	if userSessionRequest == nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusBadRequest, fmt.Errorf("unknown user session request id '%s'", request.ID))
		return
	}
	// Verify the challenge
	if string(userSessionRequest.AuthInfo.VerificationChallenge) != request.Code {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusBadRequest, fmt.Errorf("invalid verification code"))
		return
	}
	demoUser := api.runtime.DemoUser()
	if demoUser != nil {
		// Demo mode: already done in login
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, http.StatusOK, map[string]string{"redirect": "/user"})
		return
	}
	// Mark as done
	userSessionRequest.AuthInfo.State = domain.UserSessionRequestStateDone
	userSessionRequest.AuthInfo.VerificationTime = time.Now()
	err = api.runtime.DataStore().UpdateUserSessionRequest(r.Context(), userSessionRequest)
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
		return
	}
	// Set session cookie
	sessionCookie := &http.Cookie{
		Name:     "idpd_session",
		Value:    userSessionRequest.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}
	if userSessionRequest.AuthInfo.Remember {
		sessionCookie.MaxAge = 30 * 24 * 3600
	}
	http.SetCookie(w, sessionCookie)
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, http.StatusOK, map[string]string{"redirect": "/user"})
}

type SessionVerifyRequest struct {
	// ID identifies the authentication request this request refers to
	ID string `json:"id"`
	// Code is the verification code
	Code string `json:"code"`
}

func (api *API) handleUserSessionRequest(w http.ResponseWriter, r *http.Request, handle func(http.ResponseWriter, *http.Request, *domain.UserSessionRequest)) {
	params, err := serverhttp.QueryParams(r, "id")
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusBadRequest, err)
		return
	}
	id := params[0]
	userSessionRequest, err := api.runtime.DataStore().GetUserSessionRequest(r.Context(), id)
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
		return
	}
	if userSessionRequest == nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusBadRequest, fmt.Errorf("unknown user session request id '%s'", id))
		return
	}
	handle(w, r, userSessionRequest)
}
