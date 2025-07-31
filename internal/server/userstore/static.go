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
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/text/language"
)

var StaticUpdateTime time.Time = time.Now()

type StaticUser struct {
	Subject  string
	Password string
	Profile  StaticUserProfile
	Address  StaticUserAddress
	Phone    StaticUserPhone
	Email    StaticUserEmail
	Groups   []string
}

type StaticUserProfile struct {
	Name              string
	GivenName         string
	FamilyName        string
	MiddleName        string
	Nickname          string
	Profile           string
	Picture           string
	Website           string
	Birthdate         string
	Zoneinfo          string
	Locale            string
	PreferredUsername string
}

type StaticUserAddress struct {
	Formatted  string
	Street     string
	Locality   string
	Region     string
	PostalCode string
	Country    string
}

type StaticUserPhone struct {
	Number string
}

type StaticUserEmail struct {
	Address string
}

func (user *StaticUser) toUser() *User {
	profileLocale, _ := language.Parse(user.Profile.Locale)
	return &User{
		Subject: user.Subject,
		Profile: UserProfile{
			Name:              user.Profile.Name,
			GivenName:         user.Profile.GivenName,
			FamilyName:        user.Profile.FamilyName,
			MiddleName:        user.Profile.MiddleName,
			Nickname:          user.Profile.Nickname,
			Profile:           user.Profile.Profile,
			Picture:           user.Profile.Picture,
			Website:           user.Profile.Website,
			Birthdate:         user.Profile.Birthdate,
			Zoneinfo:          user.Profile.Zoneinfo,
			Locale:            profileLocale,
			PreferredUsername: user.Profile.PreferredUsername,
			UpdatedAt:         StaticUpdateTime,
		},
		Address: UserAddress{
			Formatted:  user.Address.Formatted,
			Street:     user.Address.Street,
			Locality:   user.Address.Locality,
			Region:     user.Address.Region,
			PostalCode: user.Address.PostalCode,
			Country:    user.Address.Country,
		},
		Phone: UserPhone{
			Number: user.Phone.Number,
		},
		Email: UserEmail{
			Address: user.Email.Address,
		},
		Groups: user.Groups,
	}
}

func NewStaticBackend(users []StaticUser, logger *slog.Logger) (Backend, error) {
	logger.Debug("creating static user store")
	userMap := make(map[string]StaticUser, len(users))
	for _, user := range users {
		_, exists := userMap[user.Subject]
		if !exists {
			userMap[user.Subject] = user
		} else {
			logger.Warn("duplicate static user entry", slog.String("subject", user.Subject))
		}
	}
	backend := &staticBackend{
		users:  userMap,
		logger: logger,
	}
	return backend, nil
}

type staticBackend struct {
	users  map[string]StaticUser
	logger *slog.Logger
}

func (backend *staticBackend) LookupUser(subject string) (*User, error) {
	backend.logger.Debug("looking up user", slog.String("subject", subject))
	user, err := backend.lookupUser(subject)
	if err != nil {
		return nil, err
	}
	return user.toUser(), nil
}

func (backend *staticBackend) lookupUser(subject string) (*StaticUser, error) {
	user, exists := backend.users[subject]
	if !exists {
		return nil, fmt.Errorf("%w (subject: %s)", ErrUserNotFound, subject)
	}
	return &user, nil
}

func (backend *staticBackend) CheckPassword(subject string, password string) error {
	backend.logger.Debug("checking user password", slog.String("subject", subject))
	user, err := backend.lookupUser(subject)
	if err != nil {
		return err
	}
	if user.Password != password {
		return fmt.Errorf("%w (subject: %s)", ErrIncorrectPassword, subject)
	}
	return nil
}
