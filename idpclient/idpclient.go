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

package idpclient

import (
	"net/url"

	"github.com/gorilla/securecookie"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
)

func newCookieHandler(url *url.URL) *httphelper.CookieHandler {
	hashKey := securecookie.GenerateRandomKey(64)
	encryptKey := securecookie.GenerateRandomKey(32)
	opts := make([]httphelper.CookieHandlerOpt, 0, 1)
	if url.Scheme == "http" {
		opts = append(opts, httphelper.WithUnsecure())
	}
	return httphelper.NewCookieHandler(hashKey, encryptKey, opts...)
}
