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

package tomlfile_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/userstore"
	"github.com/tdrn-org/idpd/internal/userstore/tomlfile"
)

func TestOpenClose(t *testing.T) {
	// Open
	config := tomlfileTestConfig(t)
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
	// Open
	config := tomlfileTestConfig(t)
	backend, err := userstore.Open(config)
	require.NoError(t, err)

	// Lookup user (from file)
	user2, err := backend.LookupUser(t.Context(), "user2")
	require.NoError(t, err)
	require.NotNil(t, user2) // TODO: test data

	// Lookup user (from config)
	user3, err := backend.LookupUser(t.Context(), "user3")
	require.NoError(t, err)
	require.NotNil(t, user3) // TODO: test data

	// Lookup unknown user
	user0, err := backend.LookupUser(t.Context(), "user0")
	require.Error(t, userstore.ErrUserNotFound, err)
	require.Nil(t, user0)

	// Close
	err = backend.Close()
	require.NoError(t, err)
}

func TestAuthenticateUser(t *testing.T) {
	// Open
	config := tomlfileTestConfig(t)
	backend, err := userstore.Open(config)
	require.NoError(t, err)

	// Authenticate user (from file)
	err = backend.AuthenticateUser(t.Context(), "user2", "password2")
	require.NoError(t, err)

	// Authenticate user (from config)
	err = backend.AuthenticateUser(t.Context(), "user3", "password3")
	require.NoError(t, err)

	// Authenticate user with wrong password
	err = backend.AuthenticateUser(t.Context(), "user3", "password2")
	require.Error(t, userstore.ErrNotAuthenticated, err)

	// Close
	err = backend.Close()
	require.NoError(t, err)
}

func tomlfileTestConfig(_ *testing.T) *tomlfile.Config {
	config := &tomlfile.Config{
		File: "testdata/users.toml",
		Users: []*tomlfile.User{
			{
				Login:      "user3",
				Password:   "password3",
				Name:       "User Three",
				GivenName:  "User",
				FamilyName: "Three",
				Nickname:   "Three",
				Birthdate:  time.Date(2003, 2, 3, 0, 0, 0, 0, time.Local),
				Groups:     make(map[string]*tomlfile.Group),
			},
		},
	}
	return config
}
