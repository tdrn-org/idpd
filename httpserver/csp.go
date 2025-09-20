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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type ContentSecurityPolicy struct {
	DefaultSrc   []string
	ConnectSrc   []string
	ScriptSrc    []string
	StyleSrc     []string
	ImgSrc       []string
	scriptHashes map[string][]string
	styleHashes  map[string][]string
}

func (p *ContentSecurityPolicy) AddHashes(fs fs.ReadDirFS) error {
	return p.addHashes(fs, ".")
}

func (p *ContentSecurityPolicy) addHashes(fs fs.ReadDirFS, dir string) error {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read directory '%s' (cause: %w)", dir, err)
	}
	for _, entry := range entries {
		entryType := entry.Type()
		entryName := entry.Name()
		entryPath := filepath.Join(dir, entryName)
		if entryType.IsRegular() {
			err = p.addFileHashes(fs, entryPath)
		} else if entryType.IsDir() {
			err = p.addHashes(fs, entryPath)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *ContentSecurityPolicy) addFileHashes(fs fs.ReadDirFS, path string) error {
	if !strings.HasSuffix(path, ".html") {
		return nil
	}
	file, err := fs.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file '%s' (cause: %w)", path, err)
	}
	defer file.Close()
	node, err := html.Parse(file)
	if err != nil {
		return fmt.Errorf("failed to parse file '%s' (cause: %w)", path, err)
	}
	p.addNodeHashes(path, node)
	return nil
}

func (p *ContentSecurityPolicy) addNodeHashes(path string, node *html.Node) {
	if node.DataAtom == atom.Script {
		hash := p.generateHash(node.FirstChild.Data)
		if p.scriptHashes == nil {
			p.scriptHashes = make(map[string][]string)
		}
		p.scriptHashes[path] = append(p.scriptHashes[path], hash)
	}
	for _, attr := range node.Attr {
		if attr.Key == "style" {
			hash := p.generateHash(attr.Val)
			if p.styleHashes == nil {
				p.styleHashes = make(map[string][]string)
			}
			p.styleHashes[path] = append(p.styleHashes[path], hash)
		}
	}
	for child := range node.ChildNodes() {
		p.addNodeHashes(path, child)
	}
}

func (p *ContentSecurityPolicy) generateHash(data string) string {
	alg := sha256.New()
	alg.Write([]byte(data))
	return "'sha256-" + base64.StdEncoding.EncodeToString(alg.Sum(nil)) + "'"
}

func (p *ContentSecurityPolicy) Header() *ContentSecurityPolicyHeader {
	policyCount := len(p.scriptHashes)
	if policyCount < len(p.styleHashes) {
		policyCount = len(p.styleHashes)
	}
	policies := make(map[string]string, policyCount)
	for path := range p.scriptHashes {
		policies[path] = p.policy(path)
	}
	for path := range p.styleHashes {
		policy := policies[path]
		if policy == "" {
			policies[path] = p.policy(path)
		}
	}
	defaultPolicy := "default-src: 'none';"
	return &ContentSecurityPolicyHeader{policies: policies, defaultPolicy: defaultPolicy}
}

func (p *ContentSecurityPolicy) policy(path string) string {
	buffer := &contentSecurityPolicyBuilder{}
	if len(p.DefaultSrc) > 0 {
		buffer.AddFetchDirective("default-src", p.DefaultSrc)
	}
	if len(p.ConnectSrc) > 0 {
		buffer.AddFetchDirective("connect-src", p.ConnectSrc)
	}
	pathScriptHashes := p.scriptHashes[path]
	if len(p.ScriptSrc) > 0 || len(pathScriptHashes) > 0 {
		buffer.AddFetchDirective("script-src", p.ScriptSrc, pathScriptHashes)
	}
	pathStyleHashes := p.styleHashes[path]
	if len(p.StyleSrc) > 0 || len(pathStyleHashes) > 0 {
		buffer.AddFetchDirective("style-src", p.StyleSrc, pathStyleHashes)
	}
	if len(p.ImgSrc) > 0 {
		buffer.AddFetchDirective("img-src", p.ImgSrc)
	}
	return buffer.String()
}

type ContentSecurityPolicyHeader struct {
	policies      map[string]string
	defaultPolicy string
}

func (h *ContentSecurityPolicyHeader) Apply(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" || strings.HasSuffix(path, "/") {
		path = path + "index.html"
	}
	policy := h.policies[path]
	if policy == "" {
		policy = h.defaultPolicy
	}
	w.Header().Add("Content-Security-Policy", policy)
}

type contentSecurityPolicyBuilder struct {
	strings.Builder
}

func (b *contentSecurityPolicyBuilder) AddFetchDirective(directive string, srcs ...[]string) {
	b.WriteString(directive)
	ignoreHashes := false
	for _, src := range srcs {
		for _, srcEntry := range src {
			if ignoreHashes && strings.HasPrefix(srcEntry, "'sha256-") {
				continue
			}
			ignoreHashes = ignoreHashes || (srcEntry == "'unsafe-inline'")
			b.WriteRune(' ')
			b.WriteString(srcEntry)
		}
	}
	b.WriteRune(';')
}
