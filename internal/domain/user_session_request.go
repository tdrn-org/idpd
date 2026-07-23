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

	// IntegryContext associated with this request
	IC IntegrityContext

	// AuthInfo payload which protected by the associated IntegrityContext
	AuthInfo UserSessionRequestAuthInfo

	// CreateTime is the moment this request was created.
	CreateTime time.Time
}

type UserSessionRequestAuthInfo struct {
	// Handler identifies which auth handler owns this request ("oauth2", "saml2", ...).
	Handler string `json:"handler"`

	// State tracks the request lifecycle.
	State UserSessionRequestState

	// Login is the authenticated user identity (set after successful credential check).
	Login string `json:"login"`

	// Remember indicates whether the user wants a persistent (long-lived) session.
	Remember bool `json:"remember"`

	// StrongVerificationRequired indicates whether the resulting session must use strong verification.
	StrongVerificationRequired bool `json:"strong_verification_required"`

	// LoginTime records when login was completed.
	LoginTime time.Time `json:"login_time"`

	// Verification is the method used to verify the user's identity.
	Verification Verification `json:"verification"`

	// VerificationChallenge stores the verification challenge data (e.g. hashed email code).
	VerificationChallenge []byte `json:"verification_challenge"`

	// VerificationTime records when verification was completed.
	VerificationTime time.Time `json:"verificition_time"`

	// SessionID is a UUID generated at request creation, carried through the entire flow.
	SessionID string `json:"session_id"`
}

// UserSessionRequestStore is the persistence port for UserSessionRequest.
// Implemented by data.Store.
type UserSessionRequestStore interface {
	// CreateUserSessionRequest creates and persists a new user session request for the given handler.
	CreateUserSessionRequest(ctx context.Context, handler string) error

	// GetUserSessionRequest returns the request with the given ID, or nil if not found.
	GetUserSessionRequest(ctx context.Context, id string) (*UserSessionRequest, error)

	// UpdateUserSessionRequest persists changes to an existing request.
	UpdateUserSessionRequest(ctx context.Context, request *UserSessionRequest) error
}
