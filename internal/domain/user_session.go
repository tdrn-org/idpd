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

// Session represents an authenticated user session.
// It is created when a UserSessionRequest reaches the "done" state.
type UserSession struct {
	// ID is the unique session identifier.
	ID string

	// Login is the authenticated user identity.
	Login string

	// Remember indicates whether this session persists beyond the browser session.
	Remember bool

	// Verification is the method used during authentication.
	Verification Verification

	// Terminated flags whether the session has been explicitly ended.
	Terminated bool

	// CreateTime is when the session was created.
	CreateTime time.Time

	// LastAccessTime is the last time this session was used.
	LastAccessTime time.Time
}

// IsValid returns true if the session is still valid (e.g. has not been terminated or expired).
func (s *UserSession) IsValid() bool {
	return !s.Terminated
}

// UserSessionStore is the persistence port for UserSession.
// Implemented by data.Store.
type UserSessionStore interface {
	// CreateUserSession creates and persists a new user session based on the given user session request.
	CreateUserSession(ctx context.Context, request *UserSessionRequest) (*UserSession, error)

	// GetUserSession returns the session with the given ID, or nil if not found.
	GetUserSession(ctx context.Context, id string) (*UserSession, error)

	// UpdateUserSession persists changes to an existing session.
	UpdateUserSession(ctx context.Context, session *UserSession) error
}
