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

package demo

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/tdrn-org/idpd/internal/userstore"
	"github.com/tdrn-org/idpd/internal/userstore/tomlfile"
	"golang.org/x/text/language"
)

const Type userstore.Type = "demo"

type User struct {
	Login          string            `toml:"login"`
	Password       string            `toml:"password"`
	Name           string            `toml:"name"`
	GivenName      string            `toml:"given_name"`
	FamilyName     string            `toml:"family_name"`
	MiddleName     string            `toml:"middle_name"`
	Nickname       string            `toml:"nickname"`
	Picture        string            `toml:"picture"`
	Website        string            `toml:"website"`
	Birthdate      time.Time         `toml:"birthdate"`
	Timezone       string            `toml:"timezone"`
	Locale         language.Tag      `toml:"locale"`
	EmailAddresses []string          `toml:"email_addresses"`
	PhoneNumbers   []string          `toml:"phone_numbers"`
	Addresses      []*UserAddress    `toml:"addresses"`
	Groups         map[string]*Group `toml:"groups"`
}

type UserAddress struct {
	Formatted  string `toml:"formatted"`
	Street     string `toml:"street"`
	Locality   string `toml:"locality"`
	Region     string `toml:"region"`
	PostalCode string `toml:"postal_code"`
	Country    string `toml:"country"`
}

type Group struct {
	Name string `toml:"name"`
}

type Config struct {
	User *tomlfile.User
}

func (*Config) Type() userstore.Type {
	return Type
}

func (c *Config) StoreName() string {
	return "'demo'"
}

type demoBackend struct {
	config *Config
	logger *slog.Logger
}

func open(config userstore.Config) (userstore.Backend, error) {
	demoConfig, ok := config.(*Config)
	if !ok {
		return nil, fmt.Errorf("not a demo configuration")
	}
	logger := slog.With(slog.String("userstore", fmt.Sprintf("%s/%s", config.Type(), config.StoreName())))
	backend := &demoBackend{
		config: demoConfig,
		logger: logger,
	}
	return backend, nil
}

func (b *demoBackend) Type() userstore.Type {
	return b.config.Type()
}

func (b *demoBackend) StoreName() string {
	return b.config.StoreName()
}

func (b *demoBackend) LookupUser(_ context.Context, _ string) (*userstore.User, error) {
	userstoreUser := &userstore.User{
		ID:             b.config.User.Login,
		Login:          b.config.User.Login,
		Name:           b.config.User.Name,
		GivenName:      b.config.User.GivenName,
		FamilyName:     b.config.User.FamilyName,
		MiddleName:     b.config.User.MiddleName,
		Nickname:       b.config.User.Nickname,
		Picture:        b.config.User.Picture,
		Website:        b.config.User.Website,
		Birthdate:      b.config.User.Birthdate,
		Timezone:       b.config.User.Timezone,
		Locale:         b.config.User.Locale,
		EmailAddresses: b.config.User.EmailAddresses,
		PhoneNumbers:   b.config.User.PhoneNumbers,
		Groups:         make(map[string]*userstore.Group, len(b.config.User.Groups)),
	}
	for _, address := range b.config.User.Addresses {
		userstoreUserAddress := &userstore.UserAddress{
			Formatted:  address.Formatted,
			Street:     address.Street,
			Locality:   address.Locality,
			Region:     address.Region,
			PostalCode: address.PostalCode,
			Country:    address.Country,
		}
		userstoreUser.Addresses = append(userstoreUser.Addresses, userstoreUserAddress)
	}
	for groupID, group := range b.config.User.Groups {
		userstoreUserGroup := &userstore.Group{
			ID:   groupID,
			Name: group.Name,
		}
		userstoreUser.Groups[userstoreUserGroup.ID] = userstoreUserGroup
	}
	return userstoreUser, nil
}

func (b *demoBackend) AuthenticateUser(_ context.Context, _, _ string) error {
	return nil
}

func (*demoBackend) Ping(_ context.Context) error {
	return nil
}

func (*demoBackend) Close() error {
	return nil
}

func init() {
	userstore.RegisterBackend(Type, open)
}
