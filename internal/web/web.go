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
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"

	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/go-httpserver/csp"
	"github.com/tdrn-org/idpd/internal/i18n"
	"golang.org/x/text/language"
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
	const policyNone = "'none'"
	const policySelf = "'self'"
	const policyUnsafeInline = "'unsafe-inline'"
	const dataSrc = "data:"
	contentSecurityPolicy := &csp.ContentSecurityPolicy{
		BaseUri:       []string{policySelf},
		FormAction:    []string{policySelf},
		FrameAncestor: []string{policyNone},
		DefaultSrc:    []string{policyNone},
		ConnectSrc:    []string{policySelf},
		ScriptSrc:     []string{policySelf},
		StyleSrc:      []string{policySelf, policyUnsafeInline},
		ImgSrc:        []string{policySelf, dataSrc},
	}
	err = contentSecurityPolicy.AddHashes(csp.HashAlgSHA256, docs)
	if err != nil {
		return fmt.Errorf("failed to generate csp hashes (cause: %w)", err)
	}
	instance.Handle("/", httpserver.HeaderHandler(http.FileServerFS(docs),
		contentSecurityPolicy.Header(),
		httpserver.StaticHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
		httpserver.StaticHeader("Referrer-Policy", "strict-origin-when-cross-origin"),
		httpserver.StaticHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
		httpserver.StaticHeader("X-Content-Type-Options", "nosniff"),
		httpserver.StaticHeader("X-Frame-Options", "DENY"),
		httpserver.StaticHeader("Cache-Control", "public, max-age=86400, immutable")))
	return nil
}

func Messages(locale language.Tag) (map[string]string, error) {
	fileName := filepath.Join("messages", i18n.FileName(".json", locale))
	file, err := messagesFS.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open messages bundle '%s' (cause: %w)", fileName, err)
	}
	defer file.Close()
	var messages map[string]string
	err = json.NewDecoder(file).Decode(&messages)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message bundle '%s' (cause: %w)", fileName, err)
	}
	return messages, nil
}
