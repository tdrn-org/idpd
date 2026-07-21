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

// Session represents an authenticated user session.
// It is created when a UserSessionRequest reaches the "done" state.
type Session struct {
	// ID is the unique session identifier.
	ID string

	// UserSessionRequestID references the auth request that created this session.
	UserSessionRequestID string

	// Login is the authenticated user identity.
	Login string

	// Verification is the method used during authentication.
	Verification Verification

	// Strong indicates whether this is a strong session (can satisfy strong-required requests).
	Strong bool

	// Remember indicates whether this session persists beyond the browser session.
	Remember bool

	// Terminated flags whether the session has been explicitly ended.
	Terminated bool

	// VerificationAuditInfo describes where/when verification occurred.
	VerificationAuditInfo string

	// LastAccessAuditInfo describes where/when this session was last accessed.
	LastAccessAuditInfo string

	// CreateTime is when the session was created.
	CreateTime time.Time

	// LastAccessTime is the last time this session was used.
	LastAccessTime time.Time
}

// IsActive returns true if the session has not been terminated.
func (s *Session) IsActive() bool {
	return !s.Terminated
}

// CanSatisfyStrong returns true if this session can satisfy a strong-required auth request.
func (s *Session) CanSatisfyStrong() bool {
	return s.Strong || s.Verification.Strong()
}
