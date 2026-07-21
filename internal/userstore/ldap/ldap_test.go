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

package ldap_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/userstore"
	"github.com/tdrn-org/idpd/internal/userstore/ldap"
)

func TestOpenClose(t *testing.T) {
	t.SkipNow()
	// Open
	config := activeDirectoryTestConfig(t)
	backend, err := userstore.Open(config)
	require.NoError(t, err)
	// Ping
	err = backend.Ping(t.Context())
	require.NoError(t, err)
	// Close
	err = backend.Close()
	require.NoError(t, err)
}

func TestLookupUser(t *testing.T) {
	t.SkipNow()
	// Open
	config := activeDirectoryTestConfig(t)
	backend, err := userstore.Open(config)
	require.NoError(t, err)
	// Lookup user
	user, err := backend.LookupUser(t.Context(), "")
	require.NoError(t, err)
	// TODO: test data
	require.NotNil(t, user)
	// Close
	err = backend.Close()
	require.NoError(t, err)
}

func TestAuthenticateUser(t *testing.T) {
	t.SkipNow()
	// Open
	config := activeDirectoryTestConfig(t)
	backend, err := userstore.Open(config)
	require.NoError(t, err)
	// Authenticate user
	err = backend.AuthenticateUser(t.Context(), "", "")
	require.NoError(t, err)
	// Close
	err = backend.Close()
	require.NoError(t, err)
}

func activeDirectoryTestConfig(t *testing.T) *ldap.Config {
	url0, err := url.Parse("ldap://localhost")
	require.NoError(t, err)
	config := &ldap.Config{
		URLs:         []*url.URL{url0},
		BindDN:       "",
		BindPassword: "",
		UserSearch: ldap.SearchConfig{
			BaseDN:       "",
			Scope:        2,
			DerefAliases: 0,
			Filter:       "(objectClass=user)",
		},
		UserAttributeMapping: &ldap.ActiveDirectoryMappingConfig.User,
		GroupSearch: ldap.SearchConfig{
			BaseDN:       "",
			Scope:        2,
			DerefAliases: 0,
			Filter:       "(objectClass=group)",
		},
		GroupAttributeMapping: &ldap.ActiveDirectoryMappingConfig.Group,
	}
	return config
}
