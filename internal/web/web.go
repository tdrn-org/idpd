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
	"fmt"
	"io/fs"
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
func Mount(instance *httpserver.Instance) error {
	sub, err := fs.Sub(buildFS, "build")
	if err != nil {
		return fmt.Errorf("unexpected web document structure (cause: %w)", err)
	}
	docs := sub.(fs.ReadDirFS)
	fileServer := http.FileServerFS(docs)

	// SPA fallback: serve index.html for unmatched paths (client-side routing)
	docsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		f, err := docs.Open(path)
		if err != nil {
			// File not found — fall back to index.html for SPA routing
			r.URL.Path = "/index.html"
		} else {
			f.Close()
		}
		fileServer.ServeHTTP(w, r)
	})

	// Handle("/") matches all paths — important for serving _app/immutable/* assets
	cacheControl := httpserver.StaticHeader("Cache-Control", "public, max-age=86400, immutable")
	instance.Handle("/", httpserver.HeaderHandler(docsHandler, cacheControl))
	return nil
}
