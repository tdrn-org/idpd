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

package ldap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/tdrn-org/go-pool"
	"github.com/tdrn-org/go-tlsconf/tlsclient"
	"github.com/tdrn-org/idpd/internal/userstore"
)

const Type userstore.Type = "ldap"

var ErrInvalidAttributeMapping error = errors.New("invalid attribute mapping")

type Config struct {
	URLs                  []*url.URL
	RoundRobin            bool
	ConnectionLimit       int
	KeepAliveTimeout      time.Duration
	BindDN                string
	BindPassword          string
	UserSearch            SearchConfig
	UserAttributeMapping  *UserAttributeMappingConfig
	GroupSearch           SearchConfig
	GroupAttributeMapping *GroupAttributeMappingConfig
}

type SearchConfig struct {
	BaseDN       string
	Scope        int
	DerefAliases int
	Filter       string
}

type UserAttributeMappingConfig struct {
	Login          string `toml:"login"`
	Name           string `toml:"name"`
	GivenName      string `toml:"given_name"`
	FamilyName     string `toml:"family_name"`
	Picture        string `toml:"picture"`
	Website        string `toml:"website"`
	Birthdate      string `toml:"birthdate"`
	Timezone       string `toml:"timezone"`
	Locale         string `toml:"locale"`
	EmailAddresses string `toml:"email_addresses"`
	PhoneNumbers   string `toml:"phone_numbers"`
	Street         string `toml:"street"`
	Locality       string `toml:"locality"`
	Region         string `toml:"region"`
	PostalCode     string `toml:"postal_code"`
	Country        string `toml:"country"`
	Groups         string `toml:"groups"`
	UpdatedAt      string `toml:"updated_at"`
}

type GroupAttributeMappingConfig struct {
	Name    string
	Members string
}

func (c *Config) Type() userstore.Type {
	return Type
}

func (c *Config) StoreName() string {
	buffer := &strings.Builder{}
	for _, url := range c.URLs {
		if buffer.Len() > 0 {
			buffer.WriteRune(',')
		}
		buffer.WriteString(url.Redacted())
	}
	return buffer.String()
}

type ldapBackend struct {
	config                 *Config
	userAttributeMappings  userAttributeMappingsTable
	userAttributes         []string
	groupAttributeMappings groupAttributeMappingsTable
	groupAttributes        []string
	connPool               *pool.Resources[*ldap.Conn]
	logger                 *slog.Logger
}

func open(config userstore.Config) (userstore.Backend, error) {
	ldapConfig, ok := config.(*Config)
	if !ok {
		return nil, fmt.Errorf("not a ldap configuration")
	}
	logger := slog.With(slog.String("userstore", fmt.Sprintf("%s/%s", config.Type(), config.StoreName())))
	if ldapConfig.UserAttributeMapping.Login == "" {
		return nil, fmt.Errorf("%w: user login attribute not set", ErrInvalidAttributeMapping)
	}
	if ldapConfig.UserAttributeMapping.EmailAddresses == "" {
		return nil, fmt.Errorf("%w: user email attribute not set", ErrInvalidAttributeMapping)
	}
	if ldapConfig.GroupAttributeMapping.Name == "" {
		return nil, fmt.Errorf("%w: group name attribute not set", ErrInvalidAttributeMapping)
	}
	userAttributeMappings := make(userAttributeMappingsTable)
	userAttributeMappings.bindConfig(ldapConfig.UserAttributeMapping)
	groupAttributeMappings := make(groupAttributeMappingsTable)
	groupAttributeMappings.bindConfig(ldapConfig.GroupAttributeMapping)
	backend := &ldapBackend{
		config:                 ldapConfig,
		userAttributeMappings:  userAttributeMappings,
		userAttributes:         userAttributeMappings.attributes(),
		groupAttributeMappings: groupAttributeMappings,
		groupAttributes:        groupAttributeMappings.attributes(),
		logger:                 logger,
	}
	backend.connPool = pool.NewResourcePool(fmt.Sprintf("userstore[%s/%s]", Type.String(), config.StoreName()), backend)
	backend.connPool.SetMaxTotalResources(ldapConfig.ConnectionLimit)
	backend.connPool.SetResourceMaxLifetime(ldapConfig.KeepAliveTimeout)
	return backend, nil
}

func (b *ldapBackend) Type() userstore.Type {
	return b.config.Type()
}

func (b *ldapBackend) StoreName() string {
	return b.config.StoreName()
}

func (b *ldapBackend) LookupUser(ctx context.Context, login string) (*userstore.User, error) {
	conn, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	user, err := b.lookupUser(conn, login)
	if err != nil {
		return nil, err
	}
	if b.config.UserAttributeMapping.Groups != "" {
		err = b.resolveGroupsByDN(conn, user)
	} else {
		err = b.resolveGroupsByMembers(conn, user)
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (b *ldapBackend) lookupUser(conn *pool.Resource[*ldap.Conn], login string) (*userstore.User, error) {
	userSearchFilter := fmt.Sprintf("(&(%s=%s)%s)", ldap.EscapeFilter(b.config.UserAttributeMapping.Login), ldap.EscapeFilter(login), b.config.UserSearch.Filter)
	userSearchRequest := ldap.NewSearchRequest(b.config.UserSearch.BaseDN, b.config.UserSearch.Scope, b.config.UserSearch.DerefAliases, 0, 0, false, userSearchFilter, b.userAttributes, nil)
	userSearchResult, err := conn.Get().Search(userSearchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search user")
	}
	user := &userstore.User{Groups: make(map[string]*userstore.Group)}
	switch len(userSearchResult.Entries) {
	case 0:
		return nil, userstore.ErrUserNotFound
	case 1:
		b.userAttributeMappings.mapEntry(user, userSearchResult.Entries[0], b.logger)
		return user, nil
	default:
		return nil, fmt.Errorf("non-unique user search result; check configuration")
	}
}

func (b *ldapBackend) resolveGroupsByDN(conn *pool.Resource[*ldap.Conn], user *userstore.User) error {
	groupCount := len(user.Groups)
	if groupCount == 0 {
		return nil
	}
	dns := make([]string, 0, groupCount)
	for _, group := range user.Groups {
		dns = append(dns, group.ID)
	}
	groupFilter := strings.Builder{}
	groupFilter.WriteString("(|")
	for _, dn := range dns {
		groupFilter.WriteString("(distinguishedName=")
		groupFilter.WriteString(ldap.EscapeFilter(dn))
		groupFilter.WriteString(")")
	}
	groupFilter.WriteString(")")
	groupSearchFilter := fmt.Sprintf("(&%s%s)", b.config.GroupSearch.Filter, groupFilter.String())
	groupSearchRequest := ldap.NewSearchRequest(b.config.GroupSearch.BaseDN, b.config.GroupSearch.Scope, b.config.GroupSearch.DerefAliases, 0, 0, false, groupSearchFilter, b.groupAttributes, nil)
	groupSearchResult, err := conn.Get().Search(groupSearchRequest)
	if err != nil {
		return fmt.Errorf("failed to search groups by DN")
	}
	for _, entry := range groupSearchResult.Entries {
		b.groupAttributeMappings.mapEntry(user, entry, b.logger)
	}
	return nil
}

func (b *ldapBackend) resolveGroupsByMembers(conn *pool.Resource[*ldap.Conn], user *userstore.User) error {
	groupSearchFilter := fmt.Sprintf("(&%s(%s=%s))", b.config.GroupSearch.Filter, ldap.EscapeFilter(b.config.GroupAttributeMapping.Members), ldap.EscapeFilter(user.ID))
	groupSearchRequest := ldap.NewSearchRequest(b.config.GroupSearch.BaseDN, b.config.GroupSearch.Scope, b.config.GroupSearch.DerefAliases, 0, 0, false, groupSearchFilter, b.groupAttributes, nil)
	groupSearchResult, err := conn.Get().Search(groupSearchRequest)
	if err != nil {
		return fmt.Errorf("failed to search groups by members")
	}
	for _, entry := range groupSearchResult.Entries {
		b.groupAttributeMappings.mapEntry(user, entry, b.logger)
	}
	return nil
}

func (b *ldapBackend) AuthenticateUser(ctx context.Context, login, password string) error {
	conn, err := b.bind(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	user, err := b.lookupUser(conn, login)
	if err != nil {
		return err
	}
	err = conn.Get().Bind(user.ID, password)
	if err != nil {
		return fmt.Errorf("%w (cause: %w)", userstore.ErrNotAuthenticated, err)
	}
	return nil
}

func (b *ldapBackend) Ping(ctx context.Context) error {
	conn, err := b.bind(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	return nil
}

func (b *ldapBackend) bind(ctx context.Context) (*pool.Resource[*ldap.Conn], error) {
	conn, err := b.connPool.Get(ctx)
	if err != nil {
		return nil, err
	}
	if b.config.BindPassword != "" {
		err = conn.Get().Bind(b.config.BindDN, b.config.BindPassword)
	} else {
		err = conn.Get().UnauthenticatedBind(b.config.BindDN)
	}
	if err != nil {
		defer conn.Release()
		return nil, fmt.Errorf("failed to bind (cause: %w)", err)
	}
	return conn, nil
}

func (b *ldapBackend) Close() error {
	return b.connPool.Close()
}

func (b *ldapBackend) New(_ context.Context) (*ldap.Conn, error) {
	errs := make([]error, 0)
	urls := b.config.URLs[:]
	if b.config.RoundRobin {
		rand.Shuffle(len(urls), func(i, j int) { urls[i], urls[j] = urls[j], urls[i] })
	}
	for _, url := range urls {
		opts := make([]ldap.DialOpt, 0)
		tlsConfig := tlsclient.GetConfig().Clone()
		tlsConfig.ServerName = url.Host
		opts = append(opts, ldap.DialWithTLSConfig(tlsConfig))
		conn, err := ldap.DialURL(url.String(), opts...)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func init() {
	userstore.RegisterBackend(Type, open)
}
