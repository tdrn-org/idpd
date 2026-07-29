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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/tdrn-org/go-log"
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

	// ExpiryTime is the moment this request will expire.
	ExpiryTime time.Time
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
	VerificationChallenge string `json:"verification_challenge"`

	// VerificationTime records when verification was completed.
	VerificationTime time.Time `json:"verificition_time"`
}

func (r *UserSessionRequest) IsExpired(now time.Time) bool {
	return time.Now().After(r.ExpiryTime)
}

func (r *UserSessionRequest) ReadyForLogin() bool {
	return r.AuthInfo.State == UserSessionRequestStateCreated
}

func (r *UserSessionRequest) Login(ctx context.Context, userStore UserStore, verificationHandler VerificationHandler, login, password string, remember bool) error {
	if r.AuthInfo.State != UserSessionRequestStateCreated {
		return fmt.Errorf("invalid user session request state for login: '%s'", r.AuthInfo.State)
	}
	logger := slog.With(slog.String("login", login))
	user, err := userStore.LookupUser(ctx, login)
	if err == nil {
		err = userStore.AuthenticateUser(ctx, login, password)
	}
	if err == nil {
		err = r.setVerificationChallenge(ctx, verificationHandler, user)
	}
	if err == nil {
		log.Notice(logger, "user authenticated")
		r.AuthInfo.State = UserSessionRequestStateIdentified
		r.AuthInfo.Login = login
		r.AuthInfo.Remember = remember
		r.AuthInfo.LoginTime = time.Now()
	} else if errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrNotAuthenticated) {
		r.AuthInfo.State = UserSessionRequestStateIdentified
		log.Notice(logger, "user not authenticated", slog.Any("err", err))
	} else {
		return err
	}
	return nil
}

func (r *UserSessionRequest) setVerificationChallenge(ctx context.Context, verificationHandler VerificationHandler, user *User) error {
	verification := verificationHandler.Verification()
	if r.AuthInfo.StrongVerificationRequired && !verification.IsStrong() {
		return fmt.Errorf("insufficent user session request verification method: '%s'", verification)
	}
	challenge, err := verificationHandler.GenerateChallenge(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to generate %s verification challenge for user '%s' (cause: %w)", verification, user.Login, err)
	}
	r.AuthInfo.Verification = verification
	r.AuthInfo.VerificationChallenge = challenge
	return nil
}

func (r *UserSessionRequest) Verify(ctx context.Context, verificationHandler VerificationHandler, response string) (bool, error) {
	if r.AuthInfo.State != UserSessionRequestStateIdentified {
		return false, fmt.Errorf("invalid user session request state for verify: '%s'", r.AuthInfo.State)
	}
	if r.AuthInfo.Login == "" {
		// TODO: Fake verification; at least time-wise
		return false, nil
	}
	logger := slog.With(slog.String("login", r.AuthInfo.Login))
	err := verificationHandler.VerifyResponse(ctx, r.AuthInfo.VerificationChallenge, response)
	if err == nil {
		r.AuthInfo.State = UserSessionRequestStateDone
		r.AuthInfo.VerificationTime = time.Now()
		log.Notice(logger, "user verified", slog.Any("err", err))
	} else if errors.Is(err, ErrChallengeResponseMismatch) {
		r.AuthInfo.State = UserSessionRequestStateFailed
		log.Notice(logger, "user not verified", slog.Any("err", err))
	} else {
		r.AuthInfo.State = UserSessionRequestStateFailed
	}
	return r.AuthInfo.State == UserSessionRequestStateDone, nil
}

func (r *UserSessionRequest) ReadyForVerification() bool {
	return r.AuthInfo.State == UserSessionRequestStateIdentified
}

// UserSessionRequestStore is the persistence port for UserSessionRequest.
// Implemented by data.Store.
type UserSessionRequestStore interface {
	// CreateUserSessionRequest creates and persists a new user session request for the given handler.
	CreateUserSessionRequest(ctx context.Context, handler string) (*UserSessionRequest, error)

	// GetUserSessionRequest returns the request with the given ID, or nil if not found.
	GetUserSessionRequest(ctx context.Context, id string) (*UserSessionRequest, error)

	// UpdateUserSessionRequest persists changes to an existing request.
	UpdateUserSessionRequest(ctx context.Context, request *UserSessionRequest) error
}
