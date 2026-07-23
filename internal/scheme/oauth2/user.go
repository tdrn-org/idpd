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

package oauth2

import (
	"context"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (h *Handler) populateUserinfo(ctx context.Context, userinfo *oidc.UserInfo, subject string, scopes []string) error {
	user, err := h.runtime.Users().LookupUser(ctx, subject)
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			userinfo.Subject = user.Login
		case oidc.ScopeProfile:
			userinfo.Name = user.Name
			userinfo.GivenName = user.GivenName
			userinfo.FamilyName = user.FamilyName
			userinfo.MiddleName = user.MiddleName
			userinfo.Nickname = user.Nickname
			userinfo.Picture = user.Picture
			userinfo.Website = user.Website
			if !user.Birthdate.IsZero() {
				userinfo.Birthdate = user.Birthdate.Format(time.DateOnly)
			}
			userinfo.Zoneinfo = user.Timezone
			userinfo.Locale = oidc.NewLocale(user.Locale)
			userinfo.PreferredUsername = user.Login
			userinfo.UpdatedAt = oidc.FromTime(user.UpdatedAt)
		case oidc.ScopeAddress:
			if len(user.Addresses) > 0 {
				userinfo.Address = &oidc.UserInfoAddress{
					Formatted:     user.Addresses[0].Formatted,
					StreetAddress: user.Addresses[0].Street,
					Locality:      user.Addresses[0].Locality,
					Region:        user.Addresses[0].Region,
					PostalCode:    user.Addresses[0].PostalCode,
					Country:       user.Addresses[0].Country,
				}
			}
		case oidc.ScopePhone:
			if len(user.PhoneNumbers) > 0 {
				userinfo.PhoneNumber = user.PhoneNumbers[0]
				userinfo.PhoneNumberVerified = userinfo.PhoneNumber != ""
			}
		case oidc.ScopeEmail:
			if len(user.EmailAddresses) > 0 {
				userinfo.Email = user.EmailAddresses[0]
				userinfo.EmailVerified = userinfo.Email != ""
			}
		case "groups":
			userinfo.AppendClaims("groups", user.Groups)
		}
	}
	return nil
}
