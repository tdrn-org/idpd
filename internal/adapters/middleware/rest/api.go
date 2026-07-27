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
)

type Runtime interface {
	BaseURL() *url.URL
	SessionCookie() *httpserver.CookieHandler
	DataStore() *data.Store
	UserStore() domain.UserStore
	DemoUser() *domain.User
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

const (
	basePath string = "/api"

	PathPing          string = basePath + "/ping"
	PathInfo          string = basePath + "/info"
	PathSession       string = basePath + "/session"
	PathSessionLogin  string = PathSession + "/login"
	PathSessionVerify string = PathSession + "/verify"
)

func (api *API) Mount(server *httpserver.Instance) {
	handle := func(method, path string, handler http.HandlerFunc) {
		server.HandleFunc(fmt.Sprintf("%s %s", method, path), handler)
	}

	handle("GET", PathPing, api.PingGet)
	handle("GET", PathInfo, api.InfoGet)
	handle("GET", PathSession, api.SessionGet)
	handle("POST", PathSession, api.SessionPost)
	handle("DELETE", PathSession, api.SessionDelete)
	handle("GET", PathSessionLogin+"/{id}", api.SessionLoginGet)
	handle("POST", PathSessionLogin+"/{id}", api.SessionLoginPost)
	handle("GET", PathSessionVerify+"/{id}", api.SessionVerifyGet)
	handle("POST", PathSessionVerify+"/{id}", api.SessionVerifyPost)
}

// GET @BasePath/ping
//
//	@Summary		Ping server
//	@Description	Ping the server to check general health
//
//	@Produce		json
//
//	@Success		200	{object}	StatusResponse
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/ping [get]
func (api *API) PingGet(w http.ResponseWriter, r *http.Request) {
	err := api.runtime.Ping(r.Context())
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
		return
	}
	response := &StatusResponse{
		Success: true,
		Status:  http.StatusOK,
	}
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
}

// GET @BasePath/info
//
//	@Summary		Query server info
//	@Description	Query static server info like version and configured options
//
//	@Produce		json
//
//	@Success		200	{object}	ServerInfoResponse
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/info [get]
func (api *API) InfoGet(w http.ResponseWriter, r *http.Request) {
	response := &ServerInfoResponse{
		Success: true,
		Status:  http.StatusOK,
		Data: &ServerInfo{
			Version: buildinfo.Version(),
			BaseURL: api.runtime.BaseURL().String(),
		},
	}
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
}

// GET @BasePath/session
//
//	@Summary		Get current session
//	@Description	Get the current session (if a session exists)
//
//	@Produce		json
//
//	@Success		200	{object}	SessionInfoResponse
//	@Failure		401	{object}	SessionInfoResponse
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/session [get]
func (api *API) SessionGet(w http.ResponseWriter, r *http.Request) {
	api.handleWithUserSession(w, r, api.sessionGet)
}

func (api *API) sessionGet(w http.ResponseWriter, r *http.Request, userSession *domain.UserSession) {
	//TODO: Implement
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
//	@Success		200	{object}	StatusResponse
//	@Failure		401	{object}	StatusResponse
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/session [delete]
func (api *API) SessionDelete(w http.ResponseWriter, r *http.Request) {
	api.handleWithUserSession(w, r, api.sessionDelete)
}

func (api *API) sessionDelete(w http.ResponseWriter, r *http.Request, userSession *domain.UserSession) {
	//TODO: Implement
}

// GET @BasePath/session/login/{id}
//
//	@Summary		Get login information
//	@Description	Get the login information for the authentication flow associated with the given authentication request
//
//	@Accept			json
//	@Produce		json
//
//	@Param			id	path		string	true	"Authentication request ID"
//
//	@Success		200	{object}	SessionLoginInfoResponse
//	@Failure		400	{object}	SessionLoginInfoResponse
//	@Failure		403	{object}	SessionLoginInfoResponse
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Router			/api/session/login/{id} [get]
func (api *API) SessionLoginGet(w http.ResponseWriter, r *http.Request) {
	api.handleWithUserSessionRequest(w, r, api.sessionLoginGet)
}

func (api *API) sessionLoginGet(w http.ResponseWriter, r *http.Request, userSessionRequest *domain.UserSessionRequest) {
	response := &SessionLoginInfoResponse{
		Success: false,
	}
	if !userSessionRequest.ReadyForLogin() {
		response.Status = http.StatusForbidden
		response.Code = StatusCodeAuthRequestNotAccessible
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
		return
	}
	response.Success = true
	response.Status = http.StatusOK
	response.Data = &SessionLoginInfo{
		LoginHint:            userSessionRequest.AuthInfo.Login,
		Remember:             userSessionRequest.AuthInfo.Remember,
		AllowedVerifications: userSessionRequest.AllowedVerifications(),
	}
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
}

// POST @BasePath/session/login/{id}
//
//	@Summary		Create a new session
//	@Description	Initiate the authentication flow to create a new session
//
//	@Accept			json
//	@Produce		json
//
//	@Param			id		path		string				true	"Authentication request ID"
//	@Param			request	body		SessionLoginRequest	true	"Request parameters"
//
//	@Success		200		{object}	StatusResponse
//	@Failure		400		{object}	StatusResponse
//	@Failure		403		{object}	StatusResponse
//	@Failure		500		{string}	string	"Internal Server Error"
//	@Router			/api/session/login/{id} [post]
func (api *API) SessionLoginPost(w http.ResponseWriter, r *http.Request) {
	api.handleWithUserSessionRequest(w, r, api.sessionLoginPost)
}

func (api *API) sessionLoginPost(w http.ResponseWriter, r *http.Request, userSessionRequest *domain.UserSessionRequest) {
	response := &StatusResponse{
		Success: false,
	}
	defer r.Body.Close()
	request := &SessionLoginRequest{}
	err := serverhttp.DecodeApplicationJSONRequest(r, request)
	if err != nil {
		// This should not happen; respond simple and short
		response.Status = http.StatusBadRequest
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
		return
	}
	err = userSessionRequest.Login(r.Context(), api.runtime.UserStore(), request.Login, request.Password, request.Remember)
	if err != nil {
		response.Status = http.StatusInternalServerError
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
		return
	}
	err = userSessionRequest.SetVerificationChallenge(request.Verification)
	if err != nil {
		response.Status = http.StatusBadRequest
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
		return
	}
	err = api.runtime.DataStore().UpdateUserSessionRequest(r.Context(), userSessionRequest)
	if err != nil {
		response.Status = http.StatusInternalServerError
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
		return
	}
	response.Success = true
	response.Status = http.StatusOK
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
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
	api.handleWithUserSessionRequest(w, r, api.sessionVerifyGet)
}

func (api *API) sessionVerifyGet(w http.ResponseWriter, r *http.Request, userSessionRequest *domain.UserSessionRequest) {
	response := &SessionVerifyInfoResponse{
		Success: true,
	}
	if !userSessionRequest.ReadyForVerification() {
		response.Status = http.StatusForbidden
		response.Code = StatusCodeAuthRequestNotAccessible
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
		return
	}
	response.Success = true
	response.Status = http.StatusOK
	response.Data = &SessionVerifyInfo{
		Verification: userSessionRequest.AuthInfo.Verification,
	}
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
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

func (api *API) handleWithUserSessionRequest(w http.ResponseWriter, r *http.Request, handle func(http.ResponseWriter, *http.Request, *domain.UserSessionRequest)) {
	response := &StatusResponse{
		Success: false,
	}
	id := r.PathValue("id")
	if id == "" {
		// This should not happen; respond simple and short
		response.Status = http.StatusBadRequest
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
		return
	}
	userSessionRequest, err := api.runtime.DataStore().GetUserSessionRequest(r.Context(), id)
	if err != nil {
		serverhttp.SendError(api.runtime.Logger(), w, r, http.StatusInternalServerError, err)
		return
	}
	if userSessionRequest == nil || userSessionRequest.IsExpired(time.Now()) {
		// Respond in any case with 403 to not give details for reason
		response.Status = http.StatusForbidden
		response.Code = StatusCodeAuthRequestNotAccessible
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
		return
	}
	handle(w, r, userSessionRequest)
}

func (api *API) handleWithUserSession(w http.ResponseWriter, r *http.Request, handle func(http.ResponseWriter, *http.Request, *domain.UserSession)) {
	response := &StatusResponse{
		Success: false,
		Status:  http.StatusUnauthorized,
		Code:    StatusCodeNoSession,
	}
	cookie := api.runtime.SessionCookie()
	session, ok := cookie.Get(r)
	if !ok {
		serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
		return
	}
	// TODO: Delete session from DB
	_ = session
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, response.Status, response)
	// TODO: Invoke handle if UserSession exists
	_ = handle
}
