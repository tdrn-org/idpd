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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/text/language"
)

var ErrInvalidLogin = errors.New("invalid login")
var ErrUserNotFound = fmt.Errorf("%w (user not found)", ErrInvalidLogin)
var ErrIncorrectPassword = fmt.Errorf("%w (incorrect password)", ErrInvalidLogin)

type User struct {
	Subject string
	Profile UserProfile
	Address UserAddress
	Phone   UserPhone
	Email   UserEmail
	Groups  []string
}

func (user *User) SetUserInfo(userInfo *oidc.UserInfo, scopes []string) {
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			userInfo.Subject = strings.TrimSpace(user.Subject)
		case oidc.ScopeProfile:
			userInfo.Name = strings.TrimSpace(user.Profile.Name)
			userInfo.GivenName = strings.TrimSpace(user.Profile.GivenName)
			userInfo.FamilyName = strings.TrimSpace(user.Profile.FamilyName)
			userInfo.MiddleName = strings.TrimSpace(user.Profile.MiddleName)
			userInfo.Nickname = strings.TrimSpace(user.Profile.Nickname)
			userInfo.Profile = strings.TrimSpace(user.Profile.Profile)
			userInfo.Picture = strings.TrimSpace(user.Profile.Picture)
			userInfo.Website = strings.TrimSpace(user.Profile.Website)
			userInfo.Birthdate = strings.TrimSpace(user.Profile.Birthdate)
			userInfo.Zoneinfo = strings.TrimSpace(user.Profile.Zoneinfo)
			userInfo.Locale = user.Profile.userInfoLocale()
			userInfo.PreferredUsername = strings.TrimSpace(user.Profile.PreferredUsername)
			userInfo.UpdatedAt = user.Profile.userInfoUpdateAt()
		case oidc.ScopeAddress:
			userInfo.Address = user.Address.userInfoAddress()
		case oidc.ScopePhone:
			userInfo.PhoneNumber = strings.TrimSpace(user.Phone.Number)
			userInfo.PhoneNumberVerified = userInfo.PhoneNumber != ""
		case oidc.ScopeEmail:
			userInfo.Email = strings.TrimSpace(user.Email.Address)
			userInfo.EmailVerified = userInfo.Email != ""
		case "groups":
			userInfo.AppendClaims("groups", user.Groups)
		}
	}
}

type UserProfile struct {
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
	Locale            language.Tag
	PreferredUsername string
	UpdatedAt         time.Time
}

func (profile *UserProfile) userInfoLocale() *oidc.Locale {
	if profile.Locale == language.Und {
		return nil
	}
	return oidc.NewLocale(profile.Locale)
}

func (profile *UserProfile) userInfoUpdateAt() oidc.Time {
	return oidc.FromTime(profile.UpdatedAt)
}

type UserAddress struct {
	Formatted  string
	Street     string
	Locality   string
	Region     string
	PostalCode string
	Country    string
}

func (address *UserAddress) userInfoAddress() *oidc.UserInfoAddress {
	uia := &oidc.UserInfoAddress{
		Formatted:     strings.TrimSpace(address.Formatted),
		StreetAddress: strings.TrimSpace(address.Street),
		Locality:      strings.TrimSpace(address.Locality),
		Region:        strings.TrimSpace(address.Region),
		PostalCode:    strings.TrimSpace(address.PostalCode),
		Country:       strings.TrimSpace(address.Country),
	}
	if uia.Formatted == "" && uia.StreetAddress == "" && uia.Locality == "" && uia.Region == "" && uia.PostalCode == "" && uia.Country == "" {
		return nil
	}
	return uia
}

type UserPhone struct {
	Number   string
	Verified bool
}

type UserEmail struct {
	Address  string
	Verified bool
}

type Backend interface {
	LookupUser(subject string) (*User, error)
	CheckPassword(email string, password string) error
}
