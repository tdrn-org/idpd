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

package web_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/internal/i18n"
	"github.com/tdrn-org/idpd/internal/web"
)

func TestMount(t *testing.T) {
	instance, err := httpserver.Listen(context.Background(), "tcp", "localhost:0")
	require.NoError(t, err)
	defer instance.Close()
	err = web.Mount(instance)
	require.NoError(t, err)
	go func() { _ = instance.Serve() }()
	baseURL := strings.TrimSuffix(instance.BaseURL().String(), "/")
	const contentTypeHTML string = "text/html; charset=utf-8"
	const cacheControlRevalidate string = "no-cache"
	tests := []struct {
		path         string
		status       int
		contentType  string
		cacheControl string
		location     string
	}{
		{path: "/", status: http.StatusOK, contentType: contentTypeHTML, cacheControl: cacheControlRevalidate},
		{path: "/login?id=4711", status: http.StatusOK, contentType: contentTypeHTML, cacheControl: cacheControlRevalidate},
		{path: "/verify?id=4711", status: http.StatusOK, contentType: contentTypeHTML, cacheControl: cacheControlRevalidate},
		{path: "/user", status: http.StatusOK, contentType: contentTypeHTML, cacheControl: cacheControlRevalidate},
		// Not prerendered, hence served via the SPA shell, which routes client side
		{path: "/unknown/route", status: http.StatusOK, contentType: contentTypeHTML, cacheControl: cacheControlRevalidate},
		{path: "/login/?id=4711", status: http.StatusMovedPermanently, location: "/login?id=4711"},
		{path: "/robots.txt", status: http.StatusOK, contentType: "text/plain; charset=utf-8", cacheControl: cacheControlRevalidate},
		{path: "/_app/version.json", status: http.StatusOK, contentType: "application/json", cacheControl: cacheControlRevalidate},
		{path: "/_app/immutable/unknown.js", status: http.StatusNotFound},
		{path: "/unknown.js", status: http.StatusNotFound},
	}
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response, err := client.Get(baseURL + test.path)
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, test.status, response.StatusCode)
			if test.contentType != "" {
				require.Equal(t, test.contentType, response.Header.Get("Content-Type"))
			}
			if test.cacheControl != "" {
				require.Equal(t, test.cacheControl, response.Header.Get("Cache-Control"))
			}
			if test.location != "" {
				require.Equal(t, test.location, response.Header.Get("Location"))
			}
		})
	}
}

// TestMountedRoutesResolve asserts the routes this package hands out as URLs are backed
// by a prerendered document of the build. Serving them via the SPA shell would still
// yield a 200 here, but means the route is unknown to the frontend router.
func TestMountedRoutesResolve(t *testing.T) {
	instance, err := httpserver.Listen(context.Background(), "tcp", "localhost:0")
	require.NoError(t, err)
	defer instance.Close()
	err = web.Mount(instance)
	require.NoError(t, err)
	go func() { _ = instance.Serve() }()
	baseURL := instance.BaseURL()
	shell := getDocument(t, strings.TrimSuffix(baseURL.String(), "/")+"/200.html")
	for _, mountedURL := range []*url.URL{web.LoginURL(baseURL, "4711"), web.VerifyURL(baseURL, "4711")} {
		t.Run(mountedURL.Path, func(t *testing.T) {
			document := getDocument(t, mountedURL.String())
			require.NotEqual(t, shell, document, "route '%s' is not prerendered", mountedURL.Path)
		})
	}
}

func getDocument(t *testing.T, documentURL string) string {
	t.Helper()
	response, err := http.Get(documentURL)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "text/html; charset=utf-8", response.Header.Get("Content-Type"))
	document, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return string(document)
}

func TestMessages(t *testing.T) {
	messages, err := web.Messages(i18n.DefaultLocale())
	require.NoError(t, err)
	require.NotNil(t, messages)
}
