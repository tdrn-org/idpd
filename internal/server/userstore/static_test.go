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

package userstore_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/server/userstore"
)

func TestStaticBackend(t *testing.T) {
	const user0Subject = "user0"
	const user1Subject = "user1"
	users := []userstore.StaticUser{
		{
			Subject:  user0Subject,
			Password: "user0secret",
			Groups:   []string{"group1", "group2"},
			Email: userstore.StaticUserEmail{
				Address: "user0@example.org",
			},
		}, {
			Subject:  user1Subject,
			Password: "user1secret",
			Groups:   []string{"group2", "group3"},
			Email: userstore.StaticUserEmail{
				Address: "user1@example.org",
			},
		},
	}
	backend, err := userstore.NewStaticBackend(users, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, backend)

	user0, err := backend.LookupUser(user0Subject)
	require.NoError(t, err)
	require.NotNil(t, user0)
	require.Equal(t, users[0].Email.Address, user0.Email.Address)
	require.Equal(t, users[0].Groups, user0.Groups)

	err = backend.CheckPassword(user0.Subject, users[0].Password)
	require.NoError(t, err)

	err = backend.CheckPassword(user0.Subject, users[1].Password)
	require.ErrorIs(t, err, userstore.ErrIncorrectPassword)
	require.ErrorIs(t, err, userstore.ErrInvalidLogin)

	err = backend.CheckPassword("user2", "user2secret")
	require.ErrorIs(t, err, userstore.ErrUserNotFound)
	require.ErrorIs(t, err, userstore.ErrInvalidLogin)
}
