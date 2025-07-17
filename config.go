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

package idpd

import (
	_ "embed"
	"fmt"
	"log/slog"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-ldap/ldap/v3"
	"github.com/tdrn-org/go-log"
	"github.com/tdrn-org/idpd/internal/server"
	"github.com/tdrn-org/idpd/internal/server/userstore"
)

const DefaultConfig string = "/etc/idpd/idpd.toml"

type Config struct {
	Logging struct {
		Level         string `toml:"level"`
		Target        string `toml:"target"`
		Color         int    `toml:"color"`
		FileName      string `toml:"file_name"`
		FileSizeLimit int64  `toml:"file_size_limit"`
	} `toml:"logging"`
	Server struct {
		Address       string `toml:"address"`
		Protocol      string `toml:"protocol"`
		CertFile      string `toml:"cert_file"`
		KeyFile       string `toml:"key_file"`
		PublicURL     string `toml:"public_url"`
		SessionCookie string `toml:"session_cookie"`
	} `toml:"server"`
	Database struct {
		Type   string `toml:"type"`
		Memory struct {
			// No options here
		} `toml:"memory"`
		SQLite struct {
			File string `toml:"file"`
		} `toml:"sqlite"`
		Postgres struct {
			Address  string `toml:"address"`
			DB       string `toml:"db"`
			User     string `toml:"user"`
			Password string `toml:"password"`
		} `toml:"postgres"`
	} `toml:"database"`
	UserStore struct {
		Type string `toml:"type"`
		LDAP struct {
			URL           string `toml:"url"`
			BindDN        string `toml:"bind_dn"`
			BindPassword  string `toml:"bind_password"`
			UserBaseDN    string `toml:"user_base_dn"`
			UserFilter    string `toml:"user_filter"`
			GroupBaseDN   string `toml:"group_base_dn"`
			GroupFilter   string `toml:"group_filter"`
			Mapping       string `toml:"mapping"`
			CustomMapping struct {
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
			} `toml:"custom_mapping"`
		} `toml:"ldap"`
		Static []struct {
			Password string `toml:"password"`
			Profile  struct {
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
			Groups []string `toml:"groups"`
		} `toml:"static"`
	} `toml:"userstore"`
	OpenID struct {
		AllowInsecure            bool     `toml:"allow_insecure"`
		DefaultLogoutRedirectURL string   `toml:"default_logout_redirect_url"`
		SigningKeyAlgorithm      string   `toml:"signing_key_algorithm"`
		SigningKeyLifetime       int64    `toml:"signing_key_lifetime"`
		SigningKeyExpiry         int64    `toml:"signing_key_expiry"`
		Clients                  []Client `toml:"client"`
	} `toml:"openid"`
	Mock struct {
		Enabled  bool   `toml:"enabled"`
		Email    string `toml:"email"`
		Password string `toml:"password"`
		Rembemer bool   `toml:"remember"`
	} `toml:"mock"`
}

type Client struct {
	ID           string   `toml:"id"`
	Secret       string   `toml:"secret"`
	RedirectURLs []string `toml:"redirect_urls"`
}

func (client *Client) openIDClient() *server.OpenIDClient {
	return &server.OpenIDClient{
		ID:           client.ID,
		Secret:       client.Secret,
		RedirectURLs: client.RedirectURLs,
	}
}

//go:embed config_defaults.toml
var configDefaultsData string

func LoadConfig(path string) (*Config, error) {
	slog.Info("loading config", slog.String("path", path))
	config := &Config{}
	_, err := toml.Decode(configDefaultsData, config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config defaults (cause: %w)", err)
	}
	meta, err := toml.DecodeFile(path, config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config '%s' (cause: %w)", path, err)
	}
	for _, key := range meta.Undecoded() {
		slog.Warn("unexpected configuration key", slog.String("path", path), slog.Any("key", key))
	}
	return config, nil
}

func (c *Config) logConfig() *log.Config {
	return &log.Config{
		Level:         c.Logging.Level,
		AddSource:     false,
		Target:        log.Target(c.Logging.Target),
		Color:         log.Color(c.Logging.Color),
		FileName:      c.Logging.FileName,
		FileSizeLimit: c.Logging.FileSizeLimit,
	}
}

func (c *Config) ldapUserstoreConfig() (*userstore.LDAPConfig, error) {
	var mapping *userstore.LDAPAttributeMapping
	switch c.UserStore.LDAP.Mapping {
	case "active_directory":
		mapping = userstore.LDAPActiveDirectoryMapping()
	case "openldap":
		mapping = userstore.LDAPOpenLDAPMapping()
	case "custom":
		mapping = &userstore.LDAPAttributeMapping{}
		mapping.User.Profile.Name = c.UserStore.LDAP.CustomMapping.User.Profile.Name
		mapping.User.Profile.GivenName = c.UserStore.LDAP.CustomMapping.User.Profile.GivenName
		mapping.User.Profile.FamilyName = c.UserStore.LDAP.CustomMapping.User.Profile.FamilyName
		mapping.User.Profile.MiddleName = c.UserStore.LDAP.CustomMapping.User.Profile.MiddleName
		mapping.User.Profile.Nickname = c.UserStore.LDAP.CustomMapping.User.Profile.Nickname
		mapping.User.Profile.Profile = c.UserStore.LDAP.CustomMapping.User.Profile.Profile
		mapping.User.Profile.Picture = c.UserStore.LDAP.CustomMapping.User.Profile.Picture
		mapping.User.Profile.Website = c.UserStore.LDAP.CustomMapping.User.Profile.Website
		mapping.User.Profile.Birthdate = c.UserStore.LDAP.CustomMapping.User.Profile.Birthdate
		mapping.User.Profile.Zoneinfo = c.UserStore.LDAP.CustomMapping.User.Profile.Zoneinfo
		mapping.User.Profile.Locale = c.UserStore.LDAP.CustomMapping.User.Profile.Locale
		mapping.User.Profile.PreferredUsername = c.UserStore.LDAP.CustomMapping.User.Profile.PreferredUsername
		mapping.User.Profile.UpdatedAt = c.UserStore.LDAP.CustomMapping.User.Profile.UpdatedAt
		mapping.User.Address.Formatted = c.UserStore.LDAP.CustomMapping.User.Address.Formatted
		mapping.User.Address.Street = c.UserStore.LDAP.CustomMapping.User.Address.Street
		mapping.User.Address.Locality = c.UserStore.LDAP.CustomMapping.User.Address.Locality
		mapping.User.Address.Region = c.UserStore.LDAP.CustomMapping.User.Address.Region
		mapping.User.Address.PostalCode = c.UserStore.LDAP.CustomMapping.User.Address.PostalCode
		mapping.User.Address.Country = c.UserStore.LDAP.CustomMapping.User.Address.Country
		mapping.User.Phone.Number = c.UserStore.LDAP.CustomMapping.User.Phone.Number
		mapping.User.Email.Address = c.UserStore.LDAP.CustomMapping.User.Email.Address
		mapping.User.Groups = c.UserStore.LDAP.CustomMapping.User.Groups
		mapping.Group.Name = c.UserStore.LDAP.CustomMapping.Group.Name
		mapping.Group.Members = c.UserStore.LDAP.CustomMapping.Group.Members
	default:
		return nil, fmt.Errorf("unrecognized LDAP mapping: '%s'", c.UserStore.LDAP.Mapping)
	}
	err := mapping.Validate()
	if err != nil {
		return nil, err
	}
	ldapConfig := &userstore.LDAPConfig{
		URL:          c.UserStore.LDAP.URL,
		BindDN:       c.UserStore.LDAP.BindDN,
		BindPassword: c.UserStore.LDAP.BindPassword,
		UserSearch: userstore.LDAPSearchConfig{
			BaseDN:       c.UserStore.LDAP.UserBaseDN,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			Filter:       c.UserStore.LDAP.UserFilter,
		},
		GroupSearch: userstore.LDAPSearchConfig{
			BaseDN:       c.UserStore.LDAP.GroupBaseDN,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			Filter:       c.UserStore.LDAP.GroupFilter,
		},
		Mapping: mapping,
	}
	return ldapConfig, nil
}

func (c *Config) staticUsers() []userstore.StaticUser {
	users := make([]userstore.StaticUser, 0, len(c.UserStore.Static))
	for _, static := range c.UserStore.Static {
		users = append(users, userstore.StaticUser{
			Password: static.Password,
			Groups:   static.Groups,
			Profile: userstore.StaticUserProfile{
				Name:              static.Profile.Name,
				GivenName:         static.Profile.GivenName,
				FamilyName:        static.Profile.FamilyName,
				MiddleName:        static.Profile.MiddleName,
				Nickname:          static.Profile.Nickname,
				Profile:           static.Profile.Profile,
				Picture:           static.Profile.Picture,
				Website:           static.Profile.Website,
				Birthdate:         static.Profile.Birthdate,
				Zoneinfo:          static.Profile.Zoneinfo,
				Locale:            static.Profile.Locale,
				PreferredUsername: static.Profile.PreferredUsername,
			},
			Address: userstore.StaticUserAddress{
				Formatted:  static.Address.Formatted,
				Street:     static.Address.Street,
				Locality:   static.Address.Locality,
				Region:     static.Address.Region,
				PostalCode: static.Address.PostalCode,
				Country:    static.Address.Country,
			},
			Phone: userstore.StaticUserPhone{
				Number: static.Phone.Number,
			},
			Email: userstore.StaticUserEmail{
				Address: static.Email.Address,
			},
		})
	}
	return users
}

func (c *Config) OpenIDIssuerURL() string {
	issuerURL := c.Server.PublicURL
	if issuerURL == "" {
		issuerURL = c.Server.Protocol + "://" + c.Server.Address
	}
	return issuerURL
}

func (c *Config) openIDProviderConfig() *server.OpenIDProviderConfig {
	issuerURL := c.OpenIDIssuerURL()
	defaultLogoutRedirectURL := c.OpenID.DefaultLogoutRedirectURL
	if defaultLogoutRedirectURL == "" {
		defaultLogoutRedirectURL = issuerURL
	}
	return &server.OpenIDProviderConfig{
		Issuer:                   issuerURL,
		DefaultLogoutRedirectURL: defaultLogoutRedirectURL,
		SigningKeyAlgorithm:      jose.SignatureAlgorithm(c.OpenID.SigningKeyAlgorithm),
		SigningKeyLifetime:       time.Duration(c.OpenID.SigningKeyLifetime) * time.Second,
		SigningKeyExpiry:         time.Duration(c.OpenID.SigningKeyExpiry) * time.Second,
	}
}

func (c *Config) openIDClients() []*server.OpenIDClient {
	openIDClients := make([]*server.OpenIDClient, 0, len(c.OpenID.Clients))
	for _, client := range c.OpenID.Clients {
		openIDClients = append(openIDClients, client.openIDClient())
	}
	return openIDClients
}
