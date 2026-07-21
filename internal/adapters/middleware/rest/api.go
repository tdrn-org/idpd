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
	"log/slog"
	"net/http"
	"net/url"

	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/internal/buildinfo"
)

type Runtime interface {
	BaseURL() *url.URL
	Logger() *slog.Logger
	Ping(ctx context.Context) error
}

//	@title			IdPD REST API
//	@version		1.0
//	@description	IdPD identity provider server API.

//	@contact.url	https://github.com/tdrn-org/totem

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

//	@host		localhost:9123
//	@BasePath	/api/v1

type API struct {
	runtime Runtime
}

func NewAPI(runtime Runtime) *API {
	return &API{
		runtime: runtime,
	}
}

const basePath string = "/api/v1"
const PathPing string = basePath + "/ping"
const PathInfo string = basePath + "/info"

func (api *API) Mount(server *httpserver.Instance) {
	server.HandleFunc("GET "+PathPing, api.PingGet)
	server.HandleFunc("GET "+PathInfo, api.InfoGet)
}

const responseOK string = "ok"
const responseServerError string = "server error"

// GET @BasePath/ping
//
//	@Summary		Ping the server
//	@Description	Ping the server to check general health
//	@Produce		text/plain
//	@Success		200	{string}	string	"ok"
//	@Failure		500	{string}	string	"server error"
//	@Router			/api/v1/ping [get]
func (api *API) PingGet(w http.ResponseWriter, r *http.Request) {
	err := api.runtime.Ping(r.Context())
	if err != nil {
		api.sendError(w, r, http.StatusInternalServerError, err)
		return
	}
	api.sendPlainTextResponse(w, r, http.StatusOK, responseOK)
}

// GET @BasePath/info
//
//	@Summary		Query server info
//	@Description	Ping the server to check general health
//	@Produce		text/plain
//	@Success		200	{object}	ServerInfo
//	@Failure		500	{string}	string	"server error"
//	@Router			/api/v1/info [get]
func (api *API) InfoGet(w http.ResponseWriter, r *http.Request) {
	info := &ServerInfo{
		Version: buildinfo.Version(),
	}
	api.sendApplicationJSONResponse(w, r, http.StatusOK, info)
}

type ServerInfo struct {
	// The server version
	Version string `json:"version"`
}

func (api *API) sendApplicationJSONResponse(w http.ResponseWriter, r *http.Request, status int, content any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(content)
	if err != nil {
		api.runtime.Logger().Error("failed to send 'application/json' response", slog.String("path", r.URL.Path), slog.String("method", r.Method), slog.Any("err", err))
	}
}

func (api *API) sendPlainTextResponse(w http.ResponseWriter, r *http.Request, status int, content string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	_, err := w.Write([]byte(content))
	if err != nil {
		api.runtime.Logger().Error("failed to send 'text/plain' response", slog.String("path", r.URL.Path), slog.String("method", r.Method), slog.Any("err", err))
	}
}

func (api *API) sendError(w http.ResponseWriter, r *http.Request, status int, cause error) {
	if cause != nil {
		api.runtime.Logger().Error("http handler failure", slog.String("path", r.URL.Path), slog.String("method", r.Method), slog.Any("err", cause))
	}
	http.Error(w, responseServerError, status)
}
