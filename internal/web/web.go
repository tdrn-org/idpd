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

package web

import (
	"embed"
	"net/http"
	"strings"

	"github.com/tdrn-org/go-httpserver"
)

//go:embed all:build/*
var buildFS embed.FS

//go:embed all:messages/*
var messagesFS embed.FS

// Mount registers the SPA frontend on the HTTP server.
// All non-API paths serve static files from build/, falling back to index.html for client-side routing.
func Mount(instance *httpserver.Instance) {
	instance.HandleFunc("GET /", handleWeb)
}

func handleWeb(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}

	// Build the filesystem path
	fsPath := "build" + r.URL.Path
	if strings.HasSuffix(r.URL.Path, "/") {
		fsPath += "index.html"
	}

	// Try to serve the static file
	f, err := buildFS.Open(fsPath)
	if err == nil {
		f.Close()
		// Rewrite path so FileServer finds files under build/ in the embed.FS
		r.URL.Path = "/build" + r.URL.Path
		http.FileServer(http.FS(buildFS)).ServeHTTP(w, r)
		return
	}

	// SPA fallback: serve index.html for client-side routing
	indexData, err := buildFS.ReadFile("build/index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexData)
}
