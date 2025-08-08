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
	"net/url"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-ldap/ldap/v3"
	"github.com/tdrn-org/go-log"
	"github.com/tdrn-org/idpd/httpserver"
	"github.com/tdrn-org/idpd/internal/server"
	"github.com/tdrn-org/idpd/internal/server/mail"
	"github.com/tdrn-org/idpd/internal/server/userstore"
)

const DefaultConfig string = "/etc/idpd/idpd.toml"

type Config struct {
	Logging struct {
		Level          string `toml:"level"`
		Target         string `toml:"target"`
		Color          int    `toml:"color"`
		FileName       string `toml:"file_name"`
		FileSizeLimit  int64  `toml:"file_size_limit"`
		SyslogNetwork  string `toml:"syslog_network"`
		SyslogAddress  string `toml:"syslog_address"`
		SyslogEncoding string `toml:"syslog_encoding"`
		SyslogFacility int    `toml:"syslog_facility"`
	} `toml:"logging"`
	Server struct {
		Address         string         `toml:"address"`
		Protocol        ServerProtocol `toml:"protocol"`
		AccessLog       bool           `toml:"access_log"`
		CertFile        string         `toml:"cert_file"`
		KeyFile         string         `toml:"key_file"`
		PublicURL       URLSpec        `toml:"public_url"`
		SessionCookie   string         `toml:"session_cookie"`
		SessionLifetime DurationSpec   `toml:"session_lifetime"`
		RequestLifetime DurationSpec   `toml:"request_lifetime"`
		TokenLifetime   DurationSpec   `toml:"token_lifetime"`
	} `toml:"server"`
	Mail struct {
		Address     string `toml:"address"`
		User        string `toml:"user"`
		Password    string `toml:"password"`
		FromAddress string `toml:"from_address"`
		FromName    string `toml:"from_name"`
	} `toml:"mail"`
	TOTP struct {
		Issuer string `toml:"issuer"`
	} `toml:"totp"`
	GeoIP struct {
		CityDB string `toml:"city_db"`
	} `toml:"geoip"`
	Database struct {
		Type   DatabaseType `toml:"type"`
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
		Type UserStoreType `toml:"type"`
		LDAP struct {
			URLs          []URLSpec   `toml:"urls"`
			BindDN        string      `toml:"bind_dn"`
			BindPassword  string      `toml:"bind_password"`
			UserBaseDN    string      `toml:"user_base_dn"`
			UserFilter    string      `toml:"user_filter"`
			GroupBaseDN   string      `toml:"group_base_dn"`
			GroupFilter   string      `toml:"group_filter"`
			Mapping       LDAPMapping `toml:"mapping"`
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
			Subject  string `toml:"subject"`
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
	OAuth2 struct {
		DefaultLogoutRedirectURL string              `toml:"default_logout_redirect_url"`
		SigningKeyAlgorithm      SigningKeyAlgorithm `toml:"signing_key_algorithm"`
		SigningKeyLifetime       DurationSpec        `toml:"signing_key_lifetime"`
		SigningKeyExpiry         DurationSpec        `toml:"signing_key_expiry"`
		Clients                  []OAuth2Client      `toml:"client"`
	} `toml:"oauth2"`
	Mock struct {
		Enabled  bool   `toml:"enabled"`
		Subject  string `toml:"subject"`
		Password string `toml:"password"`
		Rembemer bool   `toml:"remember"`
	} `toml:"mock"`
}

type OAuth2Client struct {
	ID           string   `toml:"id"`
	Secret       string   `toml:"secret"`
	RedirectURLs []string `toml:"redirect_urls"`
}

func (c *OAuth2Client) toServerOAuth2Client() *server.OAuth2Client {
	return &server.OAuth2Client{
		ID:           c.ID,
		Secret:       c.Secret,
		RedirectURLs: c.RedirectURLs,
	}
}

//go:embed config_defaults.toml
var configDefaultsData string

func LoadConfig(path string, strict bool) (*Config, error) {
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
	strictViolation := false
	for _, key := range meta.Undecoded() {
		strictViolation = true
		slog.Warn("unexpected configuration key", slog.String("path", path), slog.Any("key", key))
	}
	if strict && strictViolation {
		return nil, fmt.Errorf("config contains unexpected keys")
	}
	return config, nil
}

func (c *Config) toLogConfig() *log.Config {
	return &log.Config{
		Level:          c.Logging.Level,
		AddSource:      false,
		Target:         log.Target(c.Logging.Target),
		Color:          log.Color(c.Logging.Color),
		FileName:       c.Logging.FileName,
		FileSizeLimit:  c.Logging.FileSizeLimit,
		SyslogNetwork:  c.Logging.SyslogNetwork,
		SyslogAddress:  c.Logging.SyslogAddress,
		SyslogEncoding: c.Logging.SyslogEncoding,
		SyslogFacility: c.Logging.SyslogFacility,
	}
}

func (c *Config) toMailConfig() *mail.MailConfig {
	return &mail.MailConfig{
		Address:     c.Mail.Address,
		User:        c.Mail.User,
		Password:    c.Mail.Password,
		FromAddress: c.Mail.FromAddress,
		FromName:    c.Mail.FromName,
	}
}

func (c *Config) toTOTPConfig(defaultIssuer string) *server.TOTPConfig {
	issuer := c.TOTP.Issuer
	if issuer == "" {
		issuer = defaultIssuer
	}
	return &server.TOTPConfig{
		Issuer: issuer,
	}
}

func (c *Config) toLDAPUserstoreConfig() (*userstore.LDAPConfig, error) {
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
	ldapURLs := make([]string, 0, len(c.UserStore.LDAP.URLs))
	for _, url := range c.UserStore.LDAP.URLs {
		ldapURLs = append(ldapURLs, url.String())
	}
	ldapConfig := &userstore.LDAPConfig{
		URLs:         ldapURLs,
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

func (c *Config) toStaticUsers() []userstore.StaticUser {
	users := make([]userstore.StaticUser, 0, len(c.UserStore.Static))
	for _, static := range c.UserStore.Static {
		users = append(users, userstore.StaticUser{
			Subject:  static.Subject,
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

func (c *Config) oauth2IssuerURL(httpServer *httpserver.Instance) (*url.URL, error) {
	rawIssuerURL := c.Server.PublicURL.String()
	if rawIssuerURL == "" {
		rawIssuerURL = string(c.Server.Protocol) + "://" + httpServer.ListenerAddr()
	}
	issuerURL, err := url.Parse(rawIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URL '%s' (cause: %w)", rawIssuerURL, err)
	}
	return issuerURL, nil
}

func (c *Config) toOAuth2ProviderConfig(httpServer *httpserver.Instance) (*server.OAuth2ProviderConfig, error) {
	issuerURL, err := c.oauth2IssuerURL(httpServer)
	if err != nil {
		return nil, err
	}
	var defaultLogoutRedirectURL *url.URL
	if c.OAuth2.DefaultLogoutRedirectURL != "" {
		defaultLogoutRedirectURL, err = url.Parse(c.OAuth2.DefaultLogoutRedirectURL)
		if err != nil {
			return nil, fmt.Errorf("invalid default logout redirect URL '%s' (cause: %w)", c.OAuth2.DefaultLogoutRedirectURL, err)
		}
	} else {
		defaultLogoutRedirectURL = issuerURL
	}
	oauth2ProviderConfig := &server.OAuth2ProviderConfig{
		IssuerURL:                issuerURL,
		DefaultLogoutRedirectURL: defaultLogoutRedirectURL,
		SigningKeyAlgorithm:      jose.SignatureAlgorithm(c.OAuth2.SigningKeyAlgorithm),
		SigningKeyLifetime:       c.OAuth2.SigningKeyLifetime.Duration,
		SigningKeyExpiry:         c.OAuth2.SigningKeyExpiry.Duration,
	}
	return oauth2ProviderConfig, nil
}

func notAStringErr(value any) error {
	return fmt.Errorf("value %v is not a string type", value)
}

type ServerProtocol string

const (
	ServerProtocolHttp  ServerProtocol = "http"
	ServerProtocolHttps ServerProtocol = "https"
)

func (p *ServerProtocol) Value() string {
	return string(*p)
}

func (p *ServerProtocol) MarshalTOML() ([]byte, error) {
	return []byte(`"` + p.Value() + `"`), nil
}

func (p *ServerProtocol) UnmarshalTOML(value any) error {
	protocol, ok := value.(string)
	if !ok {
		return notAStringErr(value)
	}
	switch protocol {
	case string(ServerProtocolHttp):
		*p = ServerProtocolHttp
	case string(ServerProtocolHttps):
		*p = ServerProtocolHttps
	default:
		return fmt.Errorf("unknown server protocol: '%s'", protocol)
	}
	return nil
}

type DatabaseType string

const (
	DatabaseTypeMemory   DatabaseType = "memory"
	DatabaseTypeSqlite   DatabaseType = "sqlite"
	DatabaseTypePostgres DatabaseType = "postgres"
)

func (t *DatabaseType) Value() string {
	return string(*t)
}

func (t *DatabaseType) MarshalTOML() ([]byte, error) {
	return []byte(`"` + t.Value() + `"`), nil
}

func (t *DatabaseType) UnmarshalTOML(value any) error {
	databaseType, ok := value.(string)
	if !ok {
		return notAStringErr(value)
	}
	switch databaseType {
	case string(DatabaseTypeMemory):
		*t = DatabaseTypeMemory
	case string(DatabaseTypeSqlite):
		*t = DatabaseTypeSqlite
	case string(DatabaseTypePostgres):
		*t = DatabaseTypePostgres
	default:
		return fmt.Errorf("unknown database type: '%s'", databaseType)
	}
	return nil
}

type UserStoreType string

const (
	UserStoreTypeLDAP   UserStoreType = "ldap"
	UserStoreTypeStatic UserStoreType = "static"
)

func (t *UserStoreType) Value() string {
	return string(*t)
}

func (t *UserStoreType) MarshalTOML() ([]byte, error) {
	return []byte(`"` + t.Value() + `"`), nil
}

func (t *UserStoreType) UnmarshalTOML(value any) error {
	userStoreType, ok := value.(string)
	if !ok {
		return notAStringErr(value)
	}
	switch userStoreType {
	case string(UserStoreTypeLDAP):
		*t = UserStoreTypeLDAP
	case string(UserStoreTypeStatic):
		*t = UserStoreTypeStatic
	default:
		return fmt.Errorf("unknown user store type: '%s'", userStoreType)
	}
	return nil
}

type LDAPMapping string

const (
	LDAPMappingActiveDirectory LDAPMapping = "active_directory"
	LDAPMappingOpenLDAP        LDAPMapping = "openldap"
	LDAPMappingCustom          LDAPMapping = "custom"
)

func (m *LDAPMapping) Value() string {
	return string(*m)
}

func (m *LDAPMapping) MarshalTOML() ([]byte, error) {
	return []byte(`"` + m.Value() + `"`), nil
}

func (m *LDAPMapping) UnmarshalTOML(value any) error {
	mapping, ok := value.(string)
	if !ok {
		return notAStringErr(value)
	}
	switch mapping {
	case string(LDAPMappingActiveDirectory):
		*m = LDAPMappingActiveDirectory
	case string(LDAPMappingOpenLDAP):
		*m = LDAPMappingOpenLDAP
	case string(LDAPMappingCustom):
		*m = LDAPMappingCustom
	default:
		return fmt.Errorf("unknown LDAP mapping: '%s'", mapping)
	}
	return nil
}

type SigningKeyAlgorithm string

const (
	SigningKeyAlgorithmRS256 SigningKeyAlgorithm = "RS256"
	SigningKeyAlgorithmES256 SigningKeyAlgorithm = "ES256"
	SigningKeyAlgorithmPS256 SigningKeyAlgorithm = "PS256"
)

func (a *SigningKeyAlgorithm) Value() string {
	return string(*a)
}

func (a *SigningKeyAlgorithm) MarshalTOML() ([]byte, error) {
	return []byte(`"` + a.Value() + `"`), nil
}

func (a *SigningKeyAlgorithm) UnmarshalTOML(value any) error {
	algorithm, ok := value.(string)
	if !ok {
		return notAStringErr(value)
	}
	switch algorithm {
	case string(SigningKeyAlgorithmRS256):
		*a = SigningKeyAlgorithmRS256
	case string(SigningKeyAlgorithmES256):
		*a = SigningKeyAlgorithmES256
	case string(SigningKeyAlgorithmPS256):
		*a = SigningKeyAlgorithmPS256
	default:
		return fmt.Errorf("unknown signing key algorithm: '%s'", algorithm)
	}
	return nil
}

type DurationSpec struct {
	time.Duration
}

func (d *DurationSpec) Value() string {
	return d.String()
}

func (d *DurationSpec) MarshalTOML() ([]byte, error) {
	return []byte(`"` + d.Value() + `"`), nil
}

func (d *DurationSpec) UnmarshalTOML(value any) error {
	durationString, ok := value.(string)
	if !ok {
		return notAStringErr(value)
	}
	parsedDuration, err := time.ParseDuration(durationString)
	if err != nil {
		return fmt.Errorf("invalid duration: '%s' (cause: %w)", durationString, err)
	}
	d.Duration = parsedDuration
	return nil
}

type URLSpec struct {
	url.URL
}

func (url *URLSpec) Value() string {
	return url.String()
}

func (url *URLSpec) MarshalTOML() ([]byte, error) {
	return []byte(`"` + url.Value() + `"`), nil
}

func (url *URLSpec) UnmarshalTOML(value any) error {
	urlString, ok := value.(string)
	if !ok {
		return notAStringErr(value)
	}
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return fmt.Errorf("invalid URL: '%s' (cause: %w)", urlString, err)
	}
	url.URL = *parsedURL
	return nil
}
