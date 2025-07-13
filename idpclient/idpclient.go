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

package idpclient

import (
	"crypto/rand"
	"fmt"
	"net/url"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
)

func NewCookieHandler(url *url.URL) (*httphelper.CookieHandler, error) {
	hashKey := make([]byte, 64)
	_, err := rand.Read(hashKey)
	if err != nil {
		return nil, fmt.Errorf("failed read radnom bytes (cause: %w)", err)
	}
	encryptKey := make([]byte, 32)
	_, err = rand.Read(encryptKey)
	if err != nil {
		return nil, fmt.Errorf("failed read radnom bytes (cause: %w)", err)
	}
	opts := make([]httphelper.CookieHandlerOpt, 0, 1)
	if url.Scheme == "http" {
		opts = append(opts, httphelper.WithUnsecure())
	}
	return httphelper.NewCookieHandler(hashKey, encryptKey, opts...), nil
}
