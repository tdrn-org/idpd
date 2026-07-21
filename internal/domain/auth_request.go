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

package domain

import (
	"context"
	"net/url"
	"time"
)

// AuthHandler is implemented by each authentication scheme (forward, oauth2, saml2).
// It creates and retrieves AuthRequests that carry the shared UserSessionRequest state.
type AuthHandler interface {
	// Name returns the unique handler identifier (e.g. "user", "oidc", "saml2").
	Name() string

	// GetAuthRequest returns an existing auth request by ID, or creates a new one if id is empty.
	// When strong is true, the resulting session must use a strong verification method.
	GetAuthRequest(ctx context.Context, id string, strong bool) (AuthRequest, error)
}

// AuthRequest represents a single authentication flow instance.
// It wraps the shared UserSessionRequest and provides scheme-specific behavior.
type AuthRequest interface {
	// Handler returns the handler that created this request.
	Handler() AuthHandler

	// ID returns the unique request identifier.
	ID() string

	// SessionID returns the session identifier carried through the auth flow.
	SessionID() string

	// StrongRequired indicates whether a strong verification method is required.
	StrongRequired() bool

	// Login returns the login name provided during authentication.
	Login() string

	// Verification returns the verification method used or to be used.
	Verification() Verification

	// VerificationChallenge returns the verification challenge data (e.g. email code).
	VerificationChallenge() []byte

	// Remember indicates whether the user wants a persistent session.
	Remember() bool

	// Tainted indicates whether the auth request has been compromised (e.g. wrong password).
	Tainted() bool

	// VerificationTime returns the time when verification was completed.
	VerificationTime() time.Time

	// Authenticate records the login identity and verification method on this request.
	// Called after the user provides credentials. The verification challenge is set here.
	Authenticate(ctx context.Context, login string, verification Verification, verificationChallenge []byte, remember, tainted bool) error

	// Verify marks the auth request as successfully verified and returns the redirect URL.
	Verify(ctx context.Context, tainted bool) (*url.URL, error)

	// VerifyBySession skips the verification challenge and completes the request using
	// an existing valid session. Used when the user already has an active session.
	VerifyBySession(ctx context.Context, login string, verification Verification) (*url.URL, error)
}
