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

package idpd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/tdrn-org/go-tlsconf/tlsclient"
	"github.com/tdrn-org/idpd/config"
	"github.com/tdrn-org/idpd/internal/adapters/middleware/rest"
	"golang.org/x/oauth2"
)

func (s *Server) Handle(pattern string, handler http.Handler) *url.URL {
	path := pattern
	split := strings.IndexAny(pattern, " \t")
	if split >= 0 {
		path = strings.TrimLeft(pattern[split+1:], " \t")
	}
	s.httpServer.Handle(pattern, handler)
	return s.baseURL.JoinPath(path)
}

func (s *Server) HandleFunc(pattern string, handler http.HandlerFunc) *url.URL {
	return s.Handle(pattern, handler)
}

func (s *Server) Ping(ctx context.Context) error {
	if s.httpServer == nil {
		return fmt.Errorf("server not started")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsclient.GetConfig(),
		},
	}
	pingURL := s.httpServer.BaseURL().JoinPath(rest.PathPing).String()
	rsp, err := client.Get(pingURL)
	if err != nil {
		return fmt.Errorf("failed to access URL: '%s' (cause: %w)", pingURL, err)
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to ping URL: '%s' (status: %s)", pingURL, rsp.Status)
	}
	return nil
}

type OAuth2API interface {
	Endpoint() *oauth2.Endpoint
	AddClient(cfg *config.OAuth2ClientConfig)
}

func (s *Server) OAuth2() OAuth2API {
	for _, schemeHandler := range s.schemeHandlers {
		oauth2API, ok := schemeHandler.(OAuth2API)
		if ok {
			return oauth2API
		}
	}
	return nil
}
