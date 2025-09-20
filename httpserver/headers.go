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

package httpserver

import (
	"net/http"
)

type ApplyHeaderFunc func(w http.ResponseWriter, r *http.Request)

func (f ApplyHeaderFunc) Apply(w http.ResponseWriter, r *http.Request) {
	f(w, r)
}

type Header interface {
	Apply(w http.ResponseWriter, r *http.Request)
}

func HeaderHandler(handler http.Handler, header Header) http.Handler {
	if header == nil {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header.Apply(w, r)
		handler.ServeHTTP(w, r)
	})
}

type StaticHeader struct {
	Key   string
	Value string
}

func (h *StaticHeader) Apply(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add(h.Key, h.Value)
}
