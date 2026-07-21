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

package userstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"golang.org/x/text/language"
)

var ErrUserNotFound error = errors.New("user not found")
var ErrNotAuthenticated error = errors.New("not authenticated")

type Name string

func (n Name) String() string {
	return string(n)
}

type Config interface {
	Name() Name
	StoreName() string
}

type Backend interface {
	Config
	LookupUser(ctx context.Context, login string) (*User, error)
	AuthenticateUser(ctx context.Context, login, password string) error
	Ping(ctx context.Context) error
	io.Closer
}

type OpenFunc func(config Config) (Backend, error)

var backends map[Name]OpenFunc = make(map[Name]OpenFunc)

func RegisterBackend(name Name, open OpenFunc) {
	backends[name] = open
}

func Open(config Config) (Backend, error) {
	name := config.Name()
	open, ok := backends[name]
	if !ok {
		return nil, fmt.Errorf("unknown userstore backend name '%s'", name)
	}
	return open(config)
}

type User struct {
	ID             string
	Login          string
	Name           string
	GivenName      string
	FamilyName     string
	MiddleName     string
	Nickname       string
	Picture        string
	Website        string
	Birthdate      time.Time
	Timezone       string
	Locale         language.Tag
	EmailAddresses []string
	PhoneNumbers   []string
	Addresses      []*UserAddress
	UpdatedAt      time.Time
	Groups         map[string]*Group
}

func (u *User) GroupNames() []string {
	names := make([]string, 0, len(u.Groups))
	for _, group := range u.Groups {
		names = append(names, group.Name)
	}
	slices.Sort(names)
	return names
}

type UserAddress struct {
	Formatted  string
	Street     string
	Locality   string
	Region     string
	PostalCode string
	Country    string
}

type Group struct {
	ID   string
	Name string
}
