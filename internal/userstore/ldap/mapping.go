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
	_ "embed"
	"encoding/base64"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/go-ldap/ldap/v3"
	"github.com/tdrn-org/idpd/internal/userstore"
	"golang.org/x/text/language"
)

type AttributeMappingConfig struct {
	User  UserAttributeMappingConfig  `toml:"user"`
	Group GroupAttributeMappingConfig `toml:"group"`
}

var ActiveDirectoryMappingConfig *AttributeMappingConfig = &AttributeMappingConfig{}

//go:embed mapping.active_directory.toml
var activeDirectoryMappingConfigData string

var RFC2798MappingConfig *AttributeMappingConfig = &AttributeMappingConfig{}

//go:embed mapping.rfc2798.toml
var rfc2798MappingConfigData string

type userAttributeMappingFunc func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger)

type userAttributeMappingsTable map[string]userAttributeMappingFunc

func (mappings userAttributeMappingsTable) bindConfig(config *UserAttributeMappingConfig) {
	mappings.bindMapping(config.Login, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.Login = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Name, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.Name = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.GivenName, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.GivenName = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.FamilyName, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.FamilyName = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Picture, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.Picture = mapPictureAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Website, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.Website = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Birthdate, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.Birthdate = mapTimeAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Timezone, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.Timezone = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Locale, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.Locale = mapLanguageTagAttribute(attribute, logger)
	})
	mappings.bindMapping(config.EmailAddresses, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.EmailAddresses = mapStringsAttribute(attribute, logger)
	})
	mappings.bindMapping(config.PhoneNumbers, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.PhoneNumbers = mapStringsAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Street, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		if len(user.Addresses) == 0 {
			user.Addresses = append(user.Addresses, &userstore.UserAddress{})
		}
		user.Addresses[0].Street = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Locality, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		if len(user.Addresses) == 0 {
			user.Addresses = append(user.Addresses, &userstore.UserAddress{})
		}
		user.Addresses[0].Locality = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Region, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		if len(user.Addresses) == 0 {
			user.Addresses = append(user.Addresses, &userstore.UserAddress{})
		}
		user.Addresses[0].Region = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.PostalCode, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		if len(user.Addresses) == 0 {
			user.Addresses = append(user.Addresses, &userstore.UserAddress{})
		}
		user.Addresses[0].PostalCode = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Country, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		if len(user.Addresses) == 0 {
			user.Addresses = append(user.Addresses, &userstore.UserAddress{})
		}
		user.Addresses[0].Country = mapStringAttribute(attribute, logger)
	})
	mappings.bindMapping(config.UpdatedAt, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		user.UpdatedAt = mapTimeAttribute(attribute, logger)
	})
	mappings.bindMapping(config.Groups, func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		groupDNs := mapStringsAttribute(attribute, logger)
		for _, groupDN := range groupDNs {
			user.Groups[groupDN] = &userstore.Group{ID: groupDN}
		}
	})
}

func (mappings userAttributeMappingsTable) bindMapping(name string, mapping userAttributeMappingFunc) {
	if name == "" {
		return
	}
	nextMapping, ok := mappings[name]
	if ok {
		mappings[name] = func(user *userstore.User, attribute *ldap.EntryAttribute, logger *slog.Logger) {
			mapping(user, attribute, logger)
			nextMapping(user, attribute, logger)
		}
	} else {
		mappings[name] = mapping
	}
}

func (mappings userAttributeMappingsTable) attributes() []string {
	return slices.Collect(maps.Keys(mappings))
}

func (mappings userAttributeMappingsTable) mapEntry(user *userstore.User, entry *ldap.Entry, logger *slog.Logger) {
	user.ID = entry.DN
	for _, attribute := range entry.Attributes {
		attributeName := attribute.Name
		mapping, ok := mappings[attributeName]
		if !ok {
			continue
		}
		mapping(user, attribute, logger)
	}
}

type groupAttributeMappingFunc func(group *userstore.Group, attribute *ldap.EntryAttribute, logger *slog.Logger)

type groupAttributeMappingsTable map[string]groupAttributeMappingFunc

func (mappings groupAttributeMappingsTable) bindConfig(config *GroupAttributeMappingConfig) {
	mappings.bindMapping(config.Name, func(group *userstore.Group, attribute *ldap.EntryAttribute, logger *slog.Logger) {
		group.Name = mapStringAttribute(attribute, logger)
	})
}

func (mappings groupAttributeMappingsTable) bindMapping(name string, mapping groupAttributeMappingFunc) {
	if name == "" {
		return
	}
	nextMapping, ok := mappings[name]
	if ok {
		mappings[name] = func(group *userstore.Group, attribute *ldap.EntryAttribute, logger *slog.Logger) {
			mapping(group, attribute, logger)
			nextMapping(group, attribute, logger)
		}
	} else {
		mappings[name] = mapping
	}
}

func (mappings groupAttributeMappingsTable) attributes() []string {
	return slices.Collect(maps.Keys(mappings))
}

func (mappings groupAttributeMappingsTable) mapEntry(user *userstore.User, entry *ldap.Entry, logger *slog.Logger) {
	DN := entry.DN
	group, ok := user.Groups[DN]
	if !ok {
		group = &userstore.Group{ID: DN}
		user.Groups[DN] = group
	}
	for _, attribute := range entry.Attributes {
		attributeName := attribute.Name
		mapping, ok := mappings[attributeName]
		if !ok {
			continue
		}
		mapping(group, attribute, logger)
	}
}

func mapStringAttribute(attribute *ldap.EntryAttribute, logger *slog.Logger) string {
	stringValues := attribute.Values
	stringValue := ""
	switch len(stringValues) {
	case 0:
		// Ignore empty attribute
		return stringValue
	case 1:
		stringValue = stringValues[0]
	default:
		logger.Debug("ignoring additional string values", slog.String("attribute", attribute.Name))
		stringValue = stringValues[0]
	}
	return stringValue
}

func mapStringsAttribute(attribute *ldap.EntryAttribute, logger *slog.Logger) []string {
	return attribute.Values
}

func mapPictureAttribute(attribute *ldap.EntryAttribute, logger *slog.Logger) string {
	byteValues := attribute.ByteValues
	pictureValue := ""
	switch len(byteValues) {
	case 0:
		// Ignore empty attribute
		return pictureValue
	case 1:
		pictureValue = base64.RawStdEncoding.EncodeToString(byteValues[0])
	default:
		logger.Debug("ignoring additional picture values", slog.String("attribute", attribute.Name))
		pictureValue = base64.RawStdEncoding.EncodeToString(byteValues[0])
	}
	return pictureValue
}

func mapTimeAttribute(attribute *ldap.EntryAttribute, logger *slog.Logger) time.Time {
	stringValues := attribute.Values
	timeValue := time.Time{}
	var err error
	switch len(stringValues) {
	case 0:
		// Ignore empty attribute
		return timeValue
	case 1:
		timeValue, err = time.Parse("20060102150405.0Z", stringValues[0])
	default:
		logger.Debug("ignoring additional time values", slog.String("attribute", attribute.Name))
		timeValue, err = time.Parse("20060102150405.0Z", stringValues[0])
	}
	if err != nil {
		logger.Warn("failed to parse time value", slog.Any("err", err))
	}
	return timeValue
}

func mapLanguageTagAttribute(attribute *ldap.EntryAttribute, logger *slog.Logger) language.Tag {
	stringValues := attribute.Values
	languageTagValue := language.Tag{}
	var err error
	switch len(stringValues) {
	case 0:
		// Ignore empty attribute
		return languageTagValue
	case 1:
		languageTagValue, err = language.Parse(stringValues[0])
	default:
		logger.Debug("ignoring additional language tag values", slog.String("attribute", attribute.Name))
		languageTagValue, err = language.Parse(stringValues[0])
	}
	if err != nil {
		logger.Warn("failed to parse language tag value", slog.Any("err", err))
	}
	return languageTagValue
}

func init() {
	initAttributeConfig(activeDirectoryMappingConfigData, ActiveDirectoryMappingConfig)
	initAttributeConfig(rfc2798MappingConfigData, RFC2798MappingConfig)
}

func initAttributeConfig(data string, config *AttributeMappingConfig) {
	meta, err := toml.Decode(data, config)
	if err != nil {
		panic(err)
	}
	for _, key := range meta.Undecoded() {
		slog.Warn("unexpected LDAP attribute mapping key", slog.Any("key", key))
	}
}
