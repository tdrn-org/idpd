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

package web

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/tdrn-org/idpd/httpserver"
)

//go:embed all:build/*
var build embed.FS

func Mount(handler httpserver.Handler) {
	sub, err := fs.Sub(build, "build")
	if err != nil {
		panic(fmt.Sprintf("unexpected web document structure: %s", err))
	}
	docs := sub.(fs.ReadDirFS)
	const policyNone = "'none'"
	const policySelf = "'self'"
	const policyUnsafeInline = "'unsafe-inline'"
	const dataSrc = "data:"
	contentSecurityPolicy := &httpserver.ContentSecurityPolicy{
		BaseUri:        []string{policySelf},
		FormActions:    []string{policySelf},
		FrameAncestors: []string{policyNone},
		DefaultSrc:     []string{policyNone},
		ConnectSrc:     []string{policySelf},
		ScriptSrc:      []string{policySelf},
		StyleSrc:       []string{policySelf, policyUnsafeInline},
		ImgSrc:         []string{policySelf, dataSrc},
	}
	err = contentSecurityPolicy.AddHashes(docs)
	if err != nil {
		panic(fmt.Sprintf("failed to generate csp hashes: %s", err))
	}
	contentSecurityPolicyHeader := contentSecurityPolicy.Header()
	securityHeaders := &httpserver.StaticHeaders{
		Headers: []httpserver.StaticHeader{
			{Key: "X-Content-Type-Options", Value: "nosniff"},
			{Key: "X-Frame-Options", Value: "DENY"},
		},
	}
	handler.Handle("/", httpserver.HeaderHandler(http.FileServerFS(docs), contentSecurityPolicyHeader, securityHeaders))
}
