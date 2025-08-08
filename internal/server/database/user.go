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

package database

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type UserSessionRequest struct {
	ID         string
	Subject    string
	Remember   bool
	State      string
	Expiration int64
}

func NewUserSessionRequest(subject string, remember bool, state string) *UserSessionRequest {
	return &UserSessionRequest{
		ID:         uuid.NewString(),
		Subject:    subject,
		Remember:   remember,
		Expiration: time.Now().Add(RequestLifetime).UnixMicro(),
		State:      state,
	}
}

func (r *UserSessionRequest) Expired() bool {
	return r.Expiration < time.Now().UnixMicro()
}

type UserSession struct {
	ID           string
	Subject      string
	Remember     bool
	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiration   int64
}

func NewUserSession(token *oauth2.Token, subject string, remember bool) *UserSession {
	return &UserSession{
		ID:           uuid.NewString(),
		Subject:      subject,
		Remember:     remember,
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiration:   token.Expiry.UnixMicro(),
	}
}

func (session *UserSession) OAuth2Token() *oauth2.Token {
	expiresIn := session.Expiration - time.Now().UnixMicro()
	if expiresIn < 0 {
		expiresIn = 0
	}
	return &oauth2.Token{
		AccessToken:  session.AccessToken,
		TokenType:    session.TokenType,
		RefreshToken: session.RefreshToken,
		Expiry:       time.UnixMicro(session.Expiration),
		ExpiresIn:    expiresIn,
	}
}

type UserVerificationLog struct {
	Subject     string
	Method      string
	FirstUsed   int64
	LastUsed    int64
	Host        string
	Country     string
	CountryCode string
	City        string
	Lat         float64
	Lon         float64
}

func NewUserVerificationLog(subject string, method string, host string) *UserVerificationLog {
	now := time.Now().UnixMicro()
	return &UserVerificationLog{
		Subject:   subject,
		Method:    method,
		FirstUsed: now,
		LastUsed:  now,
		Host:      host,
	}
}

func (l *UserVerificationLog) Update(log *UserVerificationLog) {
	l.LastUsed = log.LastUsed
	l.Host = log.Host
	l.Country = log.Country
	l.CountryCode = log.CountryCode
	l.City = log.City
	l.Lat = log.Lat
	l.Lon = log.Lon
}

type UserTOTPRegistrationRequest struct {
	Subject    string
	Secret     string
	Challenge  string
	Expiration int64
}

func NewUserTOTPRegistrationRequest(subject string, secret string, challenge string) *UserTOTPRegistrationRequest {
	return &UserTOTPRegistrationRequest{
		Subject:    subject,
		Secret:     secret,
		Challenge:  challenge,
		Expiration: time.Now().Add(RequestLifetime).UnixMicro(),
	}
}

func (r *UserTOTPRegistrationRequest) Expired() bool {
	return r.Expiration < time.Now().UnixMicro()
}

type UserTOTPRegistration struct {
	Subject    string
	Secret     string
	CreateTime int64
}

func NewUserTOTPRegistrationFromRequest(request *UserTOTPRegistrationRequest) *UserTOTPRegistration {
	return &UserTOTPRegistration{
		Subject:    request.Subject,
		Secret:     request.Secret,
		CreateTime: time.Now().UnixMicro(),
	}
}

type UserWebAuthnIdentity struct {
	WebAuthnID          []byte
	WebAuthnName        string
	WebAuthnDisplayName string
}

func (wai *UserWebAuthnIdentity) WebAuthnUser() webauthn.User {
	return &WebAuthnUser{wai: wai}
}

type WebAuthnUser struct {
	wai *UserWebAuthnIdentity
}

func (wau *WebAuthnUser) WebAuthnID() []byte {
	return wau.wai.WebAuthnID
}

func (wau *WebAuthnUser) WebAuthnName() string {
	return wau.wai.WebAuthnName
}

func (wau *WebAuthnUser) WebAuthnDisplayName() string {
	return wau.wai.WebAuthnDisplayName
}

func (wau *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return nil
}
