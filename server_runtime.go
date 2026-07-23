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

package idpd

import (
	"context"
	"log/slog"
	"net/url"

	"github.com/tdrn-org/idpd/internal/data"
	"github.com/tdrn-org/idpd/internal/scheme"
)

func (s *Server) runtime() *serverRuntime {
	return &serverRuntime{server: s}
}

type serverRuntime struct {
	server *Server
}

func (runtime *serverRuntime) BaseURL() *url.URL {
	return runtime.server.baseURL
}

func (runtime *serverRuntime) DataStore() *data.Store {
	return runtime.server.dataStore
}

func (runtime *serverRuntime) Logger() *slog.Logger {
	return runtime.server.logger
}

func (runtime *serverRuntime) Ping(ctx context.Context) error {
	return runtime.server.Ping(ctx)
}

func (runtime *serverRuntime) GetHandler(name string) scheme.Handler {
	return runtime.server.schemeHandlers[scheme.Name(name)]
}
