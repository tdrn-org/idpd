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

package server

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/tdrn-org/go-conf"
	serverconf "github.com/tdrn-org/idpd/internal/server/conf"
)

type CookieHandler struct {
	name         string
	path         string
	secure       bool
	sameSite     http.SameSite
	maxAge       int
	secureCookie *securecookie.SecureCookie
}

func NewCookieHandler(name string, path string, secure bool, sameSite http.SameSite) *CookieHandler {
	cryptoSeed := sha256.Sum256([]byte(serverconf.LookupRuntime().CryptoSeed))
	secureCookie := securecookie.New(cryptoSeed[:], nil)
	h := &CookieHandler{
		name:         name,
		path:         path,
		secure:       secure,
		secureCookie: secureCookie,
	}
	serverconf.BindToRuntime(h.applyRuntimeConfig)
	return h
}

func (h *CookieHandler) applyRuntimeConfig(configuration conf.Configuration) {
	h.maxAge = int(conf.Resolve[*serverconf.Runtime](configuration).SessionLifetime.Seconds())
}

func (h *CookieHandler) set(w http.ResponseWriter, value string, maxAge int) error {
	encodedValue, err := h.secureCookie.Encode(h.name, value)
	if err != nil {
		return fmt.Errorf("failed to encode cookie (cause: %w)", err)
	}
	cookie := &http.Cookie{
		Name:     h.name,
		Value:    encodedValue,
		Path:     h.path,
		MaxAge:   maxAge,
		Secure:   h.secure,
		HttpOnly: true,
		SameSite: h.sameSite,
	}
	http.SetCookie(w, cookie)
	return nil
}

func (h *CookieHandler) Set(w http.ResponseWriter, value string, remember bool) error {
	maxAge := 0
	if remember {
		maxAge = h.maxAge
	}
	return h.set(w, value, maxAge)
}

func (h *CookieHandler) Get(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(h.name)
	if err != nil {
		return "", false
	}
	var decodedValue string
	err = h.secureCookie.Decode(h.name, cookie.Value, &decodedValue)
	if err != nil {
		slog.Warn("failed to decode cookie; ignoring it", slog.Any("err", err))
		return "", false
	}
	return decodedValue, true
}

func (h *CookieHandler) Delete(w http.ResponseWriter) {
	h.set(w, "", -1)
}
