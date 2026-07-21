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
	"time"
)

// UserSessionRequestState represents the lifecycle state of an authentication request.
type UserSessionRequestState string

const (
	UserSessionRequestStateCreated    UserSessionRequestState = "created"
	UserSessionRequestStateIdentified UserSessionRequestState = "identified"
	UserSessionRequestStateDone       UserSessionRequestState = "done"
	UserSessionRequestStateFailed     UserSessionRequestState = "failed"
)

// UserSessionRequest is the shared kernel for all authentication flows.
// It carries the common state needed by every auth handler (forward, oauth2, saml2).
// Scheme-specific extensions (OAuth2 scopes, SAML2 RelayState, etc.) are stored
// in handler-specific tables that reference this request by ID.
type UserSessionRequest struct {
	// ID is the unique request identifier.
	ID string

	// State tracks the request lifecycle.
	State UserSessionRequestState

	// HandlerName identifies which auth handler owns this request ("user", "oidc", "saml2").
	HandlerName string

	// SessionID is a UUID generated at request creation, carried through the entire flow.
	SessionID string

	// StrongRequired indicates whether the resulting session must use strong verification.
	StrongRequired bool

	// Login is the authenticated user identity (set after successful credential check).
	Login string

	// Verification is the method used to verify the user's identity.
	Verification Verification

	// VerificationChallenge stores the verification challenge data (e.g. hashed email code).
	VerificationChallenge []byte

	// Remember indicates whether the user wants a persistent (long-lived) session.
	Remember bool

	// Tainted flags whether this request has been compromised (wrong password, insufficient verification).
	Tainted bool

	// VerificationTime records when verification was completed.
	VerificationTime time.Time

	// AuthInfo carries additional authentication context (e.g. audit metadata).
	AuthInfo string

	// CreateTime is the moment this request was created.
	CreateTime time.Time
}
