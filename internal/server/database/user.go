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
	serverconf "github.com/tdrn-org/idpd/internal/server/conf"
	"golang.org/x/oauth2"
)

type UserSessionRequest struct {
	ID       string
	Subject  string
	Remember bool
	State    string
	Expiry   int64
}

func NewUserSessionRequest(subject string, remember bool, state string) *UserSessionRequest {
	return &UserSessionRequest{
		ID:       uuid.NewString(),
		Subject:  subject,
		Remember: remember,
		Expiry:   time.Now().Add(serverconf.LookupRuntime().RequestLifetime).UnixMicro(),
		State:    state,
	}
}

func (r *UserSessionRequest) Expired() bool {
	return r.Expiry < time.Now().UnixMicro()
}

type UserSession struct {
	ID            string
	Subject       string
	AccessToken   string
	TokenType     string
	RefreshToken  string
	TokenExpiry   int64
	SessionExpiry int64
}

func NewUserSession(subject string, token *oauth2.Token) *UserSession {
	return &UserSession{
		ID:            uuid.NewString(),
		Subject:       subject,
		AccessToken:   token.AccessToken,
		TokenType:     token.TokenType,
		RefreshToken:  token.RefreshToken,
		TokenExpiry:   token.Expiry.UnixMicro(),
		SessionExpiry: time.Now().Add(serverconf.LookupRuntime().SessionLifetime).UnixMicro(),
	}
}

func (s *UserSession) Refresh(token *oauth2.Token) bool {
	if s.AccessToken == token.AccessToken && s.TokenType == token.TokenType && s.RefreshToken == token.RefreshToken {
		return false
	}
	s.AccessToken = token.AccessToken
	s.TokenType = token.TokenType
	s.RefreshToken = token.RefreshToken
	s.TokenExpiry = token.Expiry.UnixMicro()
	return true
}

func (s *UserSession) Invalidate() {
	s.SessionExpiry = time.Now().UnixMicro()
}

func (s *UserSession) Expired() bool {
	return s.SessionExpiry < time.Now().UnixMicro()
}

func (s *UserSession) OAuth2Token() *oauth2.Token {
	expiresIn := s.TokenExpiry - time.Now().UnixMicro()
	if expiresIn < 0 {
		expiresIn = 0
	}
	return &oauth2.Token{
		AccessToken:  s.AccessToken,
		TokenType:    s.TokenType,
		RefreshToken: s.RefreshToken,
		Expiry:       time.UnixMicro(s.TokenExpiry),
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
	Subject   string
	Secret    string
	Challenge string
	Expiry    int64
}

func NewUserTOTPRegistrationRequest(subject string, secret string, challenge string) *UserTOTPRegistrationRequest {
	return &UserTOTPRegistrationRequest{
		Subject:   subject,
		Secret:    secret,
		Challenge: challenge,
		Expiry:    time.Now().Add(serverconf.LookupRuntime().RequestLifetime).UnixMicro(),
	}
}

func (r *UserTOTPRegistrationRequest) Expired() bool {
	return r.Expiry < time.Now().UnixMicro()
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
