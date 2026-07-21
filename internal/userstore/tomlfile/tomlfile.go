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

package tomlfile

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/tdrn-org/idpd/internal/userstore"
	"golang.org/x/text/language"
)

const Name userstore.Name = "file"

type userData struct {
	Users []*User `toml:"user"`
}

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
	File  string
	Users []*User
}

func (*Config) Name() userstore.Name {
	return Name
}

func (c *Config) StoreName() string {
	return "'" + c.File + "'"
}

type fileBackend struct {
	config *Config
	users  map[string]*User
	logger *slog.Logger
}

func open(config userstore.Config) (userstore.Backend, error) {
	fileConfig, ok := config.(*Config)
	if !ok {
		return nil, fmt.Errorf("not a tomlfile configuration")
	}
	logger := slog.With(slog.String("userstore", fmt.Sprintf("%s/%s", config.Name(), config.StoreName())))
	data := &userData{}
	if fileConfig.File != "" {
		meta, err := toml.DecodeFile(fileConfig.File, data)
		if err != nil {
			return nil, fmt.Errorf("failed to load user data from file '%s' (cause: %w)", fileConfig.File, err)
		}
		for _, key := range meta.Undecoded() {
			logger.Warn("unexpected user data key", slog.Any("key", key))
		}
	}
	data.Users = slices.Concat(data.Users, fileConfig.Users)
	users := make(map[string]*User)
	for _, user := range data.Users {
		_, exists := users[user.Login]
		if exists {
			logger.Warn("duplicate user login", slog.String("login", user.Login))
			continue
		}
		users[user.Login] = user
	}

	backend := &fileBackend{
		config: fileConfig,
		users:  users,
		logger: logger,
	}
	return backend, nil
}

func (b *fileBackend) Name() userstore.Name {
	return b.config.Name()
}

func (b *fileBackend) StoreName() string {
	return b.config.StoreName()
}

func (b *fileBackend) LookupUser(ctx context.Context, login string) (*userstore.User, error) {
	user, ok := b.users[login]
	if !ok {
		return nil, userstore.ErrUserNotFound
	}
	userstoreUser := &userstore.User{
		ID:             user.Login,
		Login:          user.Login,
		Name:           user.Name,
		GivenName:      user.GivenName,
		FamilyName:     user.FamilyName,
		MiddleName:     user.MiddleName,
		Nickname:       user.Nickname,
		Picture:        user.Picture,
		Website:        user.Website,
		Birthdate:      user.Birthdate,
		Timezone:       user.Timezone,
		Locale:         user.Locale,
		EmailAddresses: user.EmailAddresses,
		PhoneNumbers:   user.PhoneNumbers,
		Groups:         make(map[string]*userstore.Group, len(user.Groups)),
	}
	for _, address := range user.Addresses {
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
	for groupID, group := range user.Groups {
		userstoreUserGroup := &userstore.Group{
			ID:   groupID,
			Name: group.Name,
		}
		userstoreUser.Groups[userstoreUserGroup.ID] = userstoreUserGroup
	}
	return userstoreUser, nil
}

func (b *fileBackend) AuthenticateUser(ctx context.Context, login, password string) error {
	user, ok := b.users[login]
	if !ok {
		return userstore.ErrUserNotFound
	}
	if user.Password != password {
		return userstore.ErrNotAuthenticated
	}
	return nil
}

func (*fileBackend) Ping(_ context.Context) error {
	return nil
}

func (*fileBackend) Close() error {
	return nil
}

func init() {
	userstore.RegisterBackend(Name, open)
}
