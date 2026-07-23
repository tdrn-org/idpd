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

	"github.com/tdrn-org/idpd/internal/userstore"
	"github.com/tdrn-org/idpd/internal/userstore/demo"
	"github.com/tdrn-org/idpd/internal/userstore/ldap"
	"github.com/tdrn-org/idpd/internal/userstore/tomlfile"
)

type UserstoreConfig struct {
	Type       UserstoreType `toml:"type"`
	FileConfig struct {
		File  string           `toml:"file"`
		Users []*tomlfile.User `toml:"user"`
	} `toml:"file"`
	DemoConfig struct {
		User *tomlfile.User `toml:"user"`
	} `toml:"demo"`
}

type UserstoreType userstore.Type

var knownUserstoreTypes map[string]UserstoreType = map[string]UserstoreType{
	string(ldap.Type):     UserstoreType(ldap.Type),
	string(tomlfile.Type): UserstoreType(tomlfile.Type),
	string(demo.Type):     UserstoreType(demo.Type),
}

func (t *UserstoreType) Value() string {
	for value, userstoreType := range knownUserstoreTypes {
		if *t == userstoreType {
			return value
		}
	}
	slog.Warn("unexpected userstore type", slog.Any("t", *t))
	return ""
}

func (t *UserstoreType) MarshalTOML() ([]byte, error) {
	return []byte(`"` + t.Value() + `"`), nil
}

func (t *UserstoreType) UnmarshalTOML(value any) error {
	userstoreTypeString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected userstore type type %v", value)
	}
	userstoreType, ok := knownUserstoreTypes[userstoreTypeString]
	if !ok {
		return fmt.Errorf("unknown userstore type: '%s'", userstoreTypeString)
	}
	*t = userstoreType
	return nil
}
