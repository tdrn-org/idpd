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
	LDAPConfig struct {
		URLs             URLSpecs                    `toml:"urls"`
		RoundRobin       bool                        `toml:"round_robin"`
		ConnectionLimit  int                         `toml:"connection_limit"`
		KeepAliveTimeout DurationSpec                `toml:"keep_alive_timeout"`
		BindDN           string                      `toml:"bind_dn"`
		BindPassword     string                      `toml:"bind_password"`
		UserSearch       LDAPSearchConfig            `toml:"users"`
		GroupSearch      LDAPSearchConfig            `toml:"groups"`
		Mapping          LDAPMapping                 `toml:"mapping"`
		CustomMapping    ldap.AttributeMappingConfig `toml:"custom_mapping"`
	} `toml:"ldap"`
	FileConfig struct {
		File  string           `toml:"file"`
		Users []*tomlfile.User `toml:"user"`
	} `toml:"file"`
	DemoConfig struct {
		User *tomlfile.User `toml:"user"`
	} `toml:"demo"`
}

type LDAPSearchConfig struct {
	BaseDN       string    `toml:"base_dn"`
	Scope        LDAPScope `toml:"scope"`
	DerefAliases LDAPDeref `toml:"deref_aliases"`
	Filter       string    `toml:"filter"`
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

type LDAPMapping string

const (
	LDAPMappingActiveDirectory LDAPMapping = "active_directory"
	LDAPMappingRFC2798         LDAPMapping = "rfc2798"
	LDAPMappingCustom          LDAPMapping = "custom"
)

var knownLDAPMappings map[string]LDAPMapping = map[string]LDAPMapping{
	string(LDAPMappingActiveDirectory): LDAPMappingActiveDirectory,
	string(LDAPMappingRFC2798):         LDAPMappingRFC2798,
	string(LDAPMappingCustom):          LDAPMappingCustom,
}

func (m *LDAPMapping) Value() string {
	for value, mapping := range knownLDAPMappings {
		if *m == mapping {
			return value
		}
	}
	slog.Warn("unexpected LDAP mapping", slog.Any("m", *m))
	return ""
}

func (m *LDAPMapping) MarshalTOML() ([]byte, error) {
	return []byte(`"` + m.Value() + `"`), nil
}

func (m *LDAPMapping) UnmarshalTOML(value any) error {
	mappingString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected LDAP mapping type %v", value)
	}
	mapping, ok := knownLDAPMappings[mappingString]
	if !ok {
		return fmt.Errorf("unknown LDAP mapping: '%s'", mappingString)
	}
	*m = mapping
	return nil
}

type LDAPScope int

const (
	LDAPScopeBaseObject   string = "base_object"
	LDAPScopeSingleLevel  string = "single_level"
	LDAPScopeWholeSubtree string = "whole_subtree"
	LDAPScopeChildren     string = "children"
)

var knownLDAPScopes map[string]LDAPScope = map[string]LDAPScope{
	string(LDAPScopeBaseObject):   0,
	string(LDAPScopeSingleLevel):  1,
	string(LDAPScopeWholeSubtree): 2,
	string(LDAPScopeChildren):     3,
}

func (s *LDAPScope) Value() string {
	for value, scope := range knownLDAPScopes {
		if *s == scope {
			return value
		}
	}
	slog.Warn("unexpected LDAP scope", slog.Any("s", *s))
	return ""
}

func (s *LDAPScope) MarshalTOML() ([]byte, error) {
	return []byte(`"` + s.Value() + `"`), nil
}

func (s *LDAPScope) UnmarshalTOML(value any) error {
	scopeString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected LDAP scope type %v", value)
	}
	scope, ok := knownLDAPScopes[scopeString]
	if !ok {
		return fmt.Errorf("unknown LDAP scope: '%s'", scopeString)
	}
	*s = scope
	return nil
}

type LDAPDeref int

const (
	LDAPDerefNever          string = "never"
	LDAPDerefInSearching    string = "in_searching"
	LDAPDerefFindingBaseObj string = "finding_base_obj"
	LDAPDerefAlways         string = "always"
)

var knownLDAPDerefs map[string]LDAPDeref = map[string]LDAPDeref{
	string(LDAPDerefNever):          0,
	string(LDAPDerefInSearching):    1,
	string(LDAPDerefFindingBaseObj): 2,
	string(LDAPDerefAlways):         3,
}

func (d *LDAPDeref) Value() string {
	for value, deref := range knownLDAPDerefs {
		if *d == deref {
			return value
		}
	}
	slog.Warn("unexpected LDAP deref aliases", slog.Any("d", *d))
	return ""
}

func (d *LDAPDeref) MarshalTOML() ([]byte, error) {
	return []byte(`"` + d.Value() + `"`), nil
}

func (d *LDAPDeref) UnmarshalTOML(value any) error {
	derefString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected LDAP deref aliases type %v", value)
	}
	deref, ok := knownLDAPDerefs[derefString]
	if !ok {
		return fmt.Errorf("unknown LDAP scope: '%s'", derefString)
	}
	*d = deref
	return nil
}
