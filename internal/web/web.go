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
	"path"
	"strings"

	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/go-httpserver/csp"
	"github.com/tdrn-org/idpd/internal/i18n"
	"golang.org/x/text/language"
)

//go:embed all:build/*
var buildFS embed.FS

//go:embed all:messages/*
var messagesFS embed.FS

// indexDocument is served for the site root.
const indexDocument string = "index.html"

// fallbackDocument is the SPA shell emitted by the static adapter. It is served for
// client side routes which are not prerendered (see svelte.config.js).
const fallbackDocument string = "200.html"

// immutablePrefix marks the build artifacts emitted with a content hash in their name.
const immutablePrefix string = "/_app/immutable/"

// Mount registers the SPA frontend on the HTTP server.
// All non-API paths serve static documents from build/, falling back to the SPA shell for client-side routing.
func Mount(instance *httpserver.Instance) error {
	sub, err := fs.Sub(buildFS, "build")
	if err != nil {
		return fmt.Errorf("unexpected web document structure (cause: %w)", err)
	}
	docs, ok := sub.(fs.ReadDirFS)
	if !ok {
		return fmt.Errorf("unexpected web document structure (cause: %T does not implement fs.ReadDirFS)", sub)
	}
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
	err = checkDocuments(docs)
	if err != nil {
		return err
	}
	instance.Handle("/", httpserver.HeaderHandler(&spaHandler{docs: docs},
		contentSecurityPolicy.Header(),
		httpserver.StaticHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
		httpserver.StaticHeader("Referrer-Policy", "strict-origin-when-cross-origin"),
		httpserver.StaticHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
		httpserver.StaticHeader("X-Content-Type-Options", "nosniff"),
		httpserver.StaticHeader("X-Frame-Options", "DENY"),
		httpserver.HeaderFunc(cacheControlHeader)))
	return nil
}

// cacheControlHeader caches the content addressed build artifacts aggressively while
// keeping everything else (especially index.html) revalidated, so a server update is
// picked up by already running browsers.
func cacheControlHeader(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, immutablePrefix) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
}

// checkDocuments verifies the build contains the documents this package depends on. A
// mismatch means the frontend build options (see svelte.config.js) drifted away from the
// serving logic and is reported at startup instead of surfacing as a 404 per request.
func checkDocuments(docs fs.ReadDirFS) error {
	for _, document := range []string{indexDocument, fallbackDocument} {
		_, err := fs.Stat(docs, document)
		if err != nil {
			return fmt.Errorf("incomplete web document set (cause: %w)", err)
		}
	}
	return nil
}

// spaHandler serves the static build artifacts, resolving request paths the same way a
// static site host does: /login is served from login.html (prerendered) or, if the route
// is not prerendered, from the SPA shell, which then performs the routing client side.
type spaHandler struct {
	docs fs.ReadDirFS
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	// Canonicalize the request path (e.g. /login/ -> /login), as the build is generated
	// without trailing slashes, so that every route has exactly one URL.
	urlPath := path.Clean("/" + r.URL.Path)
	if urlPath != r.URL.Path {
		redirect := *r.URL
		redirect.Path = urlPath
		http.Redirect(w, r, redirect.RequestURI(), http.StatusMovedPermanently)
		return
	}
	document, found := h.resolve(urlPath)
	if !found {
		if !isClientRoute(urlPath) {
			http.NotFound(w, r)
			return
		}
		document = fallbackDocument
	}
	http.ServeFileFS(w, r, h.docs, document)
}

// resolve maps a canonical request path to a document of the build, following the
// lookup order of a static site host: the path itself, the prerendered document for
// that route and finally the route's directory index.
func (h *spaHandler) resolve(urlPath string) (string, bool) {
	name := strings.TrimPrefix(urlPath, "/")
	if name == "" {
		return indexDocument, true
	}
	if !fs.ValidPath(name) {
		return "", false
	}
	for _, candidate := range []string{name, name + ".html", path.Join(name, indexDocument)} {
		info, err := fs.Stat(h.docs, candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate, true
		}
	}
	return "", false
}

// isClientRoute checks whether the requested path may denote a client side route. Asset
// like paths are excluded to avoid responding with the SPA shell (and hence the wrong
// content type) for a missing asset.
func isClientRoute(urlPath string) bool {
	return !strings.HasPrefix(urlPath, "/_app/") && path.Ext(urlPath) == ""
}

func Messages(locale language.Tag) (map[string]string, error) {
	fileName := path.Join("messages", i18n.FileName(".json", locale))
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
