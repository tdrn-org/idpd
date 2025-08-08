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

package server

import (
	"fmt"
	"log/slog"

	"github.com/go-webauthn/webauthn/webauthn"
)

type WebAuthnConfig struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

func (c *WebAuthnConfig) NewWebAuthnProvider() (*WebAuthnProvider, error) {
	logger := slog.With("RPID", c.RPID)
	logger.Info("initializing WebAuthn provider")
	config := &webauthn.Config{
		RPID:          c.RPID,
		RPDisplayName: c.RPDisplayName,
		RPOrigins:     c.RPOrigins,
	}
	rp, err := webauthn.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn provider (cause: %w)", err)
	}
	provider := &WebAuthnProvider{
		rp:     rp,
		logger: logger,
	}
	return provider, nil
}

type WebAuthnProvider struct {
	rp     *webauthn.WebAuthn
	logger *slog.Logger
}
