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

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/server/userstore"
)

var testLDAPConfig = &userstore.LDAPConfig{
	URL:          "ldap://localhost:1389",
	BindDN:       "cn=idpd,dc=example,dc=org",
	BindPassword: "ldappassword",
	UserSearch: userstore.LDAPSearchConfig{
		BaseDN:       "ou=users,dc=example,dc=org",
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(&(objectClass=inetOrgPerson)(objectClass=posixAccount))",
	},
	GroupSearch: userstore.LDAPSearchConfig{
		BaseDN:       "ou=groups,dc=example,dc=org",
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=groupOfNames)",
	},
	Mapping: userstore.LDAPOpenLDAPMapping(),
}

func TestLDAPBackend(t *testing.T) {
	backend, err := userstore.NewLDAPBackend(testLDAPConfig, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, backend)

	user, err := backend.LookupUserByEmail("user0@example.org")
	require.NoError(t, err)
	require.NotNil(t, user)

	err = backend.CheckPassword("user0@example.org", "user0secret")
	require.NoError(t, err)
}
