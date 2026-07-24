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
	"log/slog"
	"net/http"
	"net/url"

	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/internal/buildinfo"
	serverhttp "github.com/tdrn-org/idpd/internal/http"
	"github.com/tdrn-org/idpd/internal/scheme"
)

type Runtime interface {
	BaseURL() *url.URL
	Logger() *slog.Logger
	Ping(ctx context.Context) error
	GetHandler(name string) scheme.Handler
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
//	@Summary		Ping the server
//	@Description	Ping the server to check general health
//	@Produce		text/plain
//	@Success		200	{string}	string	"ok"
//	@Failure		500	{string}	string	"server error"
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
//	@Description	Retrieve basic server info like version and configured options
//	@Produce		json
//	@Success		200	{object}	ServerInfo
//	@Failure		500	{string}	string	"server error"
//	@Router			/api/info [get]
func (api *API) InfoGet(w http.ResponseWriter, r *http.Request) {
	info := &ServerInfo{
		Version: buildinfo.Version(),
	}
	serverhttp.SendApplicationJSONResponse(api.runtime.Logger(), w, r, http.StatusOK, info)
}

type ServerInfo struct {
	// The server version
	Version string `json:"version"`
}

// GET @BasePath/session
//
//	@Summary		Get current session
//	@Description	Retrieve the current session information (if a session exists)
//	@Produce		json
//	@Success		200	{object}	SessionInfo
//	@Failure		404	{string}	string	"no session found"
//	@Failure		500	{string}	string	"server error"
//	@Router			/api/session [get]
func (api *API) SessionGet(w http.ResponseWriter, r *http.Request) {

}

type SessionInfo struct {
	StrongAuth bool `json:"strong_auth"`
}

// POST @BasePath/session
//
//	@Summary		Create a new session
//	@Description	Initiate the authentication flow to create a new session
//	@Produce		json
//	@Success		302	{string}	string.	"Redirect to Login UI"
//	@Failure		500	{string}	string	"server error"
//	@Router			/api/session [post]
func (api *API) SessionPost(w http.ResponseWriter, r *http.Request) {

}

// DELETE @BasePath/session
//
//	@Summary		Delete the current session
//	@Description	Deletes the current session (if a session exists)
//	@Produce		json
//	@Success		200	{object}	SessionInfo
//	@Failure		404	{string}	string	"no session found"
//	@Failure		500	{string}	string	"server error"
//	@Router			/api/session [post]
func (api *API) SessionDelete(w http.ResponseWriter, r *http.Request) {

}

// GET @BasePath/session/login
//
//	@Summary		Get current session
//	@Description	Retrieve the current session information (if a session exists)
//	@Produce		json
//	@Success		200	{object}	SessionInfo
//	@Failure		404	{string}	string	"no session found"
//	@Failure		500	{string}	string	"server error"
//	@Router			/api/session/login [get]
func (api *API) SessionLoginGet(w http.ResponseWriter, r *http.Request) {

}

// POST @BasePath/session/login
//
//	@Summary		Create a new session
//	@Description	Initiate the authentication flow to create a new session
//	@Produce		json
//	@Success		302	{string}	string.	"Redirect to Login UI"
//	@Failure		500	{string}	string	"server error"
//	@Router			/api/session/login [post]
func (api *API) SessionLoginPost(w http.ResponseWriter, r *http.Request) {

}

// GET @BasePath/session/verify
//
//	@Summary		Get current session
//	@Description	Retrieve the current session information (if a session exists)
//	@Produce		json
//	@Success		200	{object}	SessionInfo
//	@Failure		404	{string}	string	"no session found"
//	@Failure		500	{string}	string	"server error"
//	@Router			/api/session/verify [get]
func (api *API) SessionVerifyGet(w http.ResponseWriter, r *http.Request) {

}

// POST @BasePath/session/verify
//
//	@Summary		Create a new session
//	@Description	Initiate the authentication flow to create a new session
//	@Produce		json
//	@Success		302	{string}	string.	"Redirect to Login UI"
//	@Failure		500	{string}	string	"server error"
//	@Router			/api/session/login [post]
func (api *API) SessionVerifyPost(w http.ResponseWriter, r *http.Request) {

}
