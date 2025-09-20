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
	const noneSrc = "'none'"
	const selfSrc = "'self'"
	const unsafeInlineSrc = "'unsafe-inline'"
	const dataSrc = "data:"
	contentSecurityPolicy := &httpserver.ContentSecurityPolicy{
		DefaultSrc: []string{noneSrc},
		ConnectSrc: []string{selfSrc},
		ScriptSrc:  []string{selfSrc},
		StyleSrc:   []string{selfSrc, unsafeInlineSrc},
		ImgSrc:     []string{selfSrc, dataSrc},
	}
	err = contentSecurityPolicy.AddHashes(docs)
	if err != nil {
		panic(fmt.Sprintf("failed to generate csp hashes: %s", err))
	}
	contentSecurityPolicyHeader := contentSecurityPolicy.Header()
	handler.Handle("/", httpserver.HeaderHandler(http.FileServerFS(docs), contentSecurityPolicyHeader))
}
