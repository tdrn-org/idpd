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

package config

import (
	"fmt"
	"log/slog"

	"github.com/tdrn-org/go-notify/mail"
)

type MailConfig struct {
	Address          string       `toml:"address"`
	User             string       `toml:"user"`
	Password         string       `toml:"password"`
	FromAddress      string       `toml:"from_address"`
	FromName         string       `toml:"from_name"`
	KeepAliveTimeout DurationSpec `toml:"keep_alive_timeout"`
	TLSMode          TLSMode      `toml:"tls_mode"`
	EHLOIdentity     string       `toml:"ehlo_identity"`
}

type TLSMode mail.TLSMode

var knownTLSModes map[string]TLSMode = map[string]TLSMode{
	string(mail.TLSModeDefault):  TLSMode(mail.TLSModeDefault),
	string(mail.TLSModeNone):     TLSMode(mail.TLSModeNone),
	string(mail.TLSModeSSL):      TLSMode(mail.TLSModeSSL),
	string(mail.TLSModeStartTLS): TLSMode(mail.TLSModeStartTLS),
}

func (m *TLSMode) Value() string {
	for value, mode := range knownTLSModes {
		if *m == mode {
			return value
		}
	}
	slog.Warn("unexpected TLS mode", slog.Any("m", *m))
	return ""
}

func (m *TLSMode) MarshalTOML() ([]byte, error) {
	return []byte(`"` + m.Value() + `"`), nil
}

func (m *TLSMode) UnmarshalTOML(value any) error {
	modeString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected TLS mode type %v", value)
	}
	mode, ok := knownTLSModes[modeString]
	if !ok {
		return fmt.Errorf("unknown TLS mode: '%s'", modeString)
	}
	*m = mode
	return nil
}
