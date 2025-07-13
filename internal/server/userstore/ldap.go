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

package userstore

import (
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/language"
)

type LDAPSearchConfig struct {
	BaseDN       string
	Scope        int
	DerefAliases int
	Filter       string
}

type LDAPConfig struct {
	URL          string
	BindDN       string
	BindPassword string
	UserSearch   LDAPSearchConfig
	GroupSearch  LDAPSearchConfig
	Mapping      *LDAPAttributeMapping
}

var ErrInvalidLDAPAttributeMapping = errors.New("invalid LDAP attribute mapping")

type LDAPAttributeMapping struct {
	User struct {
		Profile struct {
			Name              string `toml:"name"`
			GivenName         string `toml:"given_name"`
			FamilyName        string `toml:"family_name"`
			MiddleName        string `toml:"middle_name"`
			Nickname          string `toml:"nickname"`
			Profile           string `toml:"profile"`
			Picture           string `toml:"picture"`
			Website           string `toml:"website"`
			Birthdate         string `toml:"birthdate"`
			Zoneinfo          string `toml:"zoneinfo"`
			Locale            string `toml:"locale"`
			PreferredUsername string `toml:"preferred_username"`
			UpdatedAt         string `toml:"update_at"`
		} `toml:"profile"`
		Address struct {
			Formatted  string `toml:"formatted"`
			Street     string `toml:"street"`
			Locality   string `toml:"locality"`
			Region     string `toml:"region"`
			PostalCode string `toml:"postal_code"`
			Country    string `toml:"country"`
		} `toml:"address"`
		Phone struct {
			Number string `toml:"number"`
		} `toml:"phone"`
		Email struct {
			Address string `toml:"address"`
		} `toml:"email"`
		Groups string `toml:"groups"`
	} `toml:"user"`
	Group struct {
		Name    string `toml:"name"`
		Members string `toml:"members"`
	} `toml:"group"`
}

func LDAPActiveDirectoryMapping() *LDAPAttributeMapping {
	mapping := &LDAPAttributeMapping{}
	mapping.mustLoad("ldap.active_directory.toml")
	return mapping
}

func LDAPOpenLDAPMapping() *LDAPAttributeMapping {
	mapping := &LDAPAttributeMapping{}
	mapping.mustLoad("ldap.openldap.toml")
	return mapping
}

//go:embed ldap.*.toml
var ldapMappings embed.FS

func (mapping *LDAPAttributeMapping) mustLoad(path string) {
	meta, err := toml.DecodeFS(ldapMappings, path, mapping)
	if err != nil {
		slog.Error("failed to decode LDAP attribute mapping", slog.String("path", path), slog.Any("err", err))
		panic(err)
	}
	for _, key := range meta.Undecoded() {
		slog.Warn("unexpected configuration key", slog.String("path", path), slog.Any("key", key))
	}
}

func (mapping *LDAPAttributeMapping) Validate() error {
	var userEmailAddressErr error
	if mapping.User.Email.Address == "" {
		userEmailAddressErr = fmt.Errorf("%w (user email address attribute missing)", ErrInvalidLDAPAttributeMapping)
	}
	var groupNameErr error
	if mapping.Group.Name == "" {
		groupNameErr = fmt.Errorf("%w (group name attribute missing)", ErrInvalidLDAPAttributeMapping)
	}
	err := errors.Join(userEmailAddressErr, groupNameErr)
	if err != nil {
		return err
	}
	return nil
}

type ldapUser struct {
	DN string
	User
}

type ldapGroup struct {
	DN   string
	Name string
}

func (mapping *LDAPAttributeMapping) mapper() *ldapAttributeMapper {
	mapper := &ldapAttributeMapper{
		Mapping:            mapping,
		UserEmailAttribute: mapping.User.Email.Address,
		GroupNameAttribute: mapping.Group.Name,
		userMappingTable:   make(map[string]func(*ldapUser, *ldap.EntryAttribute)),
		groupMappingTable:  make(map[string]func(*ldapGroup, *ldap.EntryAttribute)),
	}
	mapper.addUserMapping(mapping.User.Profile.Name, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.Name = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.GivenName, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.GivenName = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.FamilyName, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.FamilyName = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.MiddleName, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.MiddleName = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.Nickname, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.Nickname = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.Profile, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.Profile = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.Picture, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.Picture = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.Website, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.Website = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.Birthdate, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.Birthdate = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.Zoneinfo, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.Zoneinfo = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.Locale, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.Locale = mapping.mapLanguageTagValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.PreferredUsername, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.PreferredUsername = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Profile.UpdatedAt, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Profile.UpdatedAt = mapping.mapTimeValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Address.Formatted, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Address.Formatted = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Address.Street, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Address.Street = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Address.Locality, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Address.Locality = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Address.Region, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Address.Region = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Address.PostalCode, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Address.PostalCode = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Address.Country, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Address.Country = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Phone.Number, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Phone.Number = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Email.Address, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Email.Address = mapping.mapStringValue(attribute)
	})
	mapper.addUserMapping(mapping.User.Groups, func(user *ldapUser, attribute *ldap.EntryAttribute) {
		user.Groups = mapping.mapStringValues(attribute)
	})
	mapper.addGroupMapping(mapping.Group.Name, func(group *ldapGroup, attribute *ldap.EntryAttribute) {
		group.Name = mapping.mapStringValue(attribute)
	})
	return mapper
}

func (mapping *LDAPAttributeMapping) mapStringValue(attribute *ldap.EntryAttribute) string {
	values := attribute.Values
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (mapping *LDAPAttributeMapping) mapStringValues(attribute *ldap.EntryAttribute) []string {
	return attribute.Values
}

func (mapping *LDAPAttributeMapping) mapTimeValue(attribute *ldap.EntryAttribute) time.Time {
	values := attribute.Values
	if len(values) == 0 {
		return time.Time{}
	}
	time, _ := time.Parse("20060102150405.0Z", values[0])
	return time
}

func (mapping *LDAPAttributeMapping) mapLanguageTagValue(attribute *ldap.EntryAttribute) language.Tag {
	values := attribute.Values
	if len(values) == 0 {
		return language.Und
	}
	languageTag, _ := language.Parse(values[0])
	return languageTag
}

type ldapAttributeMapper struct {
	Mapping            *LDAPAttributeMapping
	UserEmailAttribute string
	GroupNameAttribute string
	userMappingTable   map[string]func(*ldapUser, *ldap.EntryAttribute)
	groupMappingTable  map[string]func(*ldapGroup, *ldap.EntryAttribute)
}

func (mapper *ldapAttributeMapper) addUserMapping(attribute string, mapping func(*ldapUser, *ldap.EntryAttribute)) {
	if attribute != "" {
		_, exists := mapper.userMappingTable[attribute]
		if exists {
			slog.Warn("ambiguous LDAP user attribute mapping", slog.String("attribute", attribute))
		}
		mapper.userMappingTable[attribute] = mapping
	}
}

func (mapper *ldapAttributeMapper) addGroupMapping(attribute string, mapping func(*ldapGroup, *ldap.EntryAttribute)) {
	if attribute != "" {
		_, exists := mapper.groupMappingTable[attribute]
		if exists {
			slog.Warn("ambiguous LDAP group attribute mapping", slog.String("attribute", attribute))
		}
		mapper.groupMappingTable[attribute] = mapping
	}
}

func (mapper *ldapAttributeMapper) userAttributes() []string {
	return slices.Collect(maps.Keys(mapper.userMappingTable))
}

func (mapper *ldapAttributeMapper) groupAttributes() []string {
	return slices.Collect(maps.Keys(mapper.groupMappingTable))
}

func (mapper *ldapAttributeMapper) mapUser(entry *ldap.Entry) *ldapUser {
	user := &ldapUser{
		DN: entry.DN,
	}
	for _, attribute := range entry.Attributes {
		mapping := mapper.userMappingTable[attribute.Name]
		if mapping != nil {
			mapping(user, attribute)
		}
	}
	user.Phone.Verified = user.Phone.Number != ""
	user.Email.Verified = user.Email.Address != ""
	return user
}

func (mapper *ldapAttributeMapper) mapGroup(entry *ldap.Entry) *ldapGroup {
	group := &ldapGroup{
		DN: entry.DN,
	}
	for _, attribute := range entry.Attributes {
		mapping := mapper.groupMappingTable[attribute.Name]
		if mapping != nil {
			mapping(group, attribute)
		}
	}
	return group
}

func NewLDAPBackend(config *LDAPConfig, logger *slog.Logger) (Backend, error) {
	err := config.Mapping.Validate()
	if err != nil {
		return nil, err
	}
	backend := &ldapBackend{
		LDAPConfig: *config,
		mapper:     config.Mapping.mapper(),
		logger:     logger,
	}
	return backend, nil
}

type ldapBackend struct {
	LDAPConfig
	mapper *ldapAttributeMapper
	logger *slog.Logger
}

func (backend *ldapBackend) LookupUserByEmail(email string) (*User, error) {
	backend.logger.Debug("looking up user by email address", slog.String("email", email))
	conn, err := backend.connectAndBind()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	user, err := backend.lookupUser(conn, email)
	if err != nil {
		return nil, err
	}
	var groups []string
	if backend.mapper.Mapping.User.Groups != "" {
		groups, err = backend.lookupUserGroups(conn, user)
	} else if backend.mapper.Mapping.Group.Members != "" {
		groups, err = backend.lookupGroupsByUser(conn, user)
	} else {
		backend.logger.Warn("no group mapping defined")
		groups = []string{}
	}
	if err != nil {
		return nil, err
	}
	user.User.Groups = groups
	return &user.User, nil
}

func (backend *ldapBackend) lookupUser(conn *ldap.Conn, email string) (*ldapUser, error) {
	userSearchFilter := fmt.Sprintf("(&(%s=%s)%s)", ldap.EscapeFilter(backend.mapper.UserEmailAttribute), ldap.EscapeFilter(email), backend.UserSearch.Filter)
	userSearchRequest := ldap.NewSearchRequest(backend.UserSearch.BaseDN, backend.UserSearch.Scope, backend.UserSearch.DerefAliases, 0, 0, false, userSearchFilter, backend.mapper.userAttributes(), nil)
	userSearchResult, err := conn.Search(userSearchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP user search failure (cause: %w)", err)
	}
	switch len(userSearchResult.Entries) {
	case 0:
		return nil, fmt.Errorf("%w (email: %s)", ErrUserNotFound, email)
	case 1:
		return backend.mapper.mapUser(userSearchResult.Entries[0]), nil
	}
	return nil, fmt.Errorf("%w (filter: %s)", ErrUserNotFound, userSearchFilter)
}

func (backend *ldapBackend) lookupUserGroups(conn *ldap.Conn, user *ldapUser) ([]string, error) {
	if len(user.Groups) == 0 {
		return []string{}, nil
	}
	groupFilter := strings.Builder{}
	groupFilter.WriteString("(|")
	for _, userGroup := range user.Groups {
		groupFilter.WriteString("(distinguishedName=")
		groupFilter.WriteString(ldap.EscapeFilter(userGroup))
		groupFilter.WriteString(")")
	}
	groupFilter.WriteString(")")
	groupSearchFilter := fmt.Sprintf("(&%s%s)", backend.GroupSearch.Filter, groupFilter.String())
	groupSearchRequest := ldap.NewSearchRequest(backend.GroupSearch.BaseDN, backend.GroupSearch.Scope, backend.GroupSearch.DerefAliases, 0, 0, false, groupSearchFilter, backend.mapper.groupAttributes(), nil)
	groupSearchResult, err := conn.Search(groupSearchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP group search failure (cause: %w)", err)
	}
	groups := make([]string, 0, len(groupSearchResult.Entries))
	for _, entry := range groupSearchResult.Entries {
		group := backend.mapper.mapGroup(entry)
		groups = append(groups, group.Name)
	}
	return groups, nil
}

func (backend *ldapBackend) lookupGroupsByUser(conn *ldap.Conn, user *ldapUser) ([]string, error) {
	groupSearchFilter := fmt.Sprintf("(&%s(%s=%s))", backend.GroupSearch.Filter, ldap.EscapeFilter(backend.mapper.Mapping.Group.Members), ldap.EscapeFilter(user.DN))
	groupSearchRequest := ldap.NewSearchRequest(backend.GroupSearch.BaseDN, backend.GroupSearch.Scope, backend.GroupSearch.DerefAliases, 0, 0, false, groupSearchFilter, backend.mapper.groupAttributes(), nil)
	groupSearchResult, err := conn.Search(groupSearchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP group search failure (cause: %w)", err)
	}
	groups := make([]string, 0, len(groupSearchResult.Entries))
	for _, entry := range groupSearchResult.Entries {
		group := backend.mapper.mapGroup(entry)
		groups = append(groups, group.Name)
	}
	return groups, nil
}

func (backend *ldapBackend) CheckPassword(email string, password string) error {
	backend.logger.Debug("checking user password", slog.String("email", email))
	conn, err := backend.connectAndBind()
	if err != nil {
		return err
	}
	defer conn.Close()
	user, err := backend.lookupUser(conn, email)
	if err != nil {
		return err
	}
	err = conn.Bind(user.DN, password)
	if err != nil {
		return errors.Join(fmt.Errorf("%w (email: %s)", ErrIncorrectPassword, email), err)
	}
	return nil
}

func (backend *ldapBackend) connectAndBind() (*ldap.Conn, error) {
	conn, err := ldap.DialURL(backend.URL)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect failure (cause: %w)", err)
	}
	err = conn.Bind(backend.BindDN, backend.BindPassword)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("LDAP bind failure (cause: %w)", err)
	}
	return conn, nil
}
