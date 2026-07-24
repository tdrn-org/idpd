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

package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

const ResponseOK string = "ok"
const ResponseBadRequest string = "bad request"
const ResponseServerError string = "server error"

func SendApplicationJSONResponse(logger *slog.Logger, w http.ResponseWriter, r *http.Request, status int, content any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(content)
	if err != nil {
		logger.Error("failed to send 'application/json' response", slog.String("path", r.URL.Path), slog.String("method", r.Method), slog.Any("err", err))
	}
}

func SendPlainTextResponse(logger *slog.Logger, w http.ResponseWriter, r *http.Request, status int, content string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	_, err := w.Write([]byte(content))
	if err != nil {
		logger.Error("failed to send 'text/plain' response", slog.String("path", r.URL.Path), slog.String("method", r.Method), slog.Any("err", err))
	}
}

func SendError(logger *slog.Logger, w http.ResponseWriter, r *http.Request, status int, cause error) {
	if cause != nil {
		logger.Error("http handler failure", slog.String("path", r.URL.Path), slog.String("method", r.Method), slog.Any("err", cause))
	}
	http.Error(w, http.StatusText(status), status)
}
