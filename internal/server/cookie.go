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
	"net/http"
)

type CookieHandler struct {
	name     string
	path     string
	secure   bool
	sameSite http.SameSite
	maxAge   int
}

func NewCookieHandler(name string, path string, secure bool, sameSite http.SameSite, maxAge int) *CookieHandler {
	return &CookieHandler{
		name:   name,
		path:   path,
		secure: secure,
		maxAge: maxAge,
	}
}

func (h *CookieHandler) set(w http.ResponseWriter, value string, maxAge int) {
	cookie := &http.Cookie{
		Name:     h.name,
		Value:    value,
		Path:     h.path,
		MaxAge:   maxAge,
		Secure:   h.secure,
		HttpOnly: true,
		SameSite: h.sameSite,
	}
	http.SetCookie(w, cookie)
}

func (h *CookieHandler) Set(w http.ResponseWriter, value string, remember bool) {
	maxAge := 0
	if remember {
		maxAge = h.maxAge
	}
	h.set(w, value, maxAge)
}

func (h *CookieHandler) Get(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(h.name)
	if err != nil {
		return "", false
	}
	return cookie.Value, true
}

func (h *CookieHandler) Delete(w http.ResponseWriter) {
	h.set(w, "", -1)
}
