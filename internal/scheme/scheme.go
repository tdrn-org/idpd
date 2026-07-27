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

package scheme

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/internal/data"
	"github.com/tdrn-org/idpd/internal/domain"
)

type Name string

func (n Name) String() string {
	return string(n)
}

type Runtime interface {
	BaseURL() *url.URL
	LoginURL(id string) *url.URL
	VerifyURL(id string) *url.URL
	DataStore() *data.Store
	UserStore() domain.UserStore
	DemoUser() *domain.User
	Logger() *slog.Logger
}

type Handler interface {
	Name() Name
	Mount(instance *httpserver.Instance)
	RedirectLogin(w http.ResponseWriter, r *http.Request) error
}
