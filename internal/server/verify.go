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

package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/tdrn-org/idpd/internal/server/mail"
	"github.com/tdrn-org/idpd/internal/server/templates"
	"github.com/tdrn-org/idpd/internal/server/userstore"
)

type VerifyMethod string

const (
	VerifyMethodNone     VerifyMethod = ""
	VerifyMethodEmail    VerifyMethod = "email"
	VerifyMethodTOTP     VerifyMethod = "totp"
	VerifyMethodPasskey  VerifyMethod = "passkey"
	VerifyMethodWebAuthn VerifyMethod = "webauthn"
)

var errUserNotAuthenticated = errors.New("user not authenticated")

const taintedChallenge = "tainted"

type VerifyHandler interface {
	Method() VerifyMethod
	Taint()
	Tainted() bool
	InitiateChallenge(ctx context.Context, subject string) (string, error)
	VerifyRepsonse(ctx context.Context, subject string, challenge string, response string) error
}

func NoneVerifyHandler() VerifyHandler {
	return &noneVerifyHandler{}
}

type noneVerifyHandler struct{}

func (*noneVerifyHandler) Method() VerifyMethod {
	return VerifyMethodNone
}

func (*noneVerifyHandler) Taint() {
	// Nothing to do here
}

func (*noneVerifyHandler) Tainted() bool {
	return true
}

func (*noneVerifyHandler) InitiateChallenge(_ context.Context, _ string) (string, error) {
	return taintedChallenge, nil
}

func (h *noneVerifyHandler) VerifyRepsonse(_ context.Context, _ string, _ string, _ string) error {
	return errUserNotAuthenticated
}

func EmailVerifyHandler(mailer *mail.Mailer, userStore userstore.Backend) VerifyHandler {
	return &emailVerifyHandler{
		mailer:    mailer,
		userStore: userStore,
	}
}

type emailVerifyHandler struct {
	mailer    *mail.Mailer
	userStore userstore.Backend
	tainted   bool
}

func (*emailVerifyHandler) Method() VerifyMethod {
	return VerifyMethodEmail
}

func (h *emailVerifyHandler) Taint() {
	h.tainted = true
}

func (h *emailVerifyHandler) Tainted() bool {
	return h.tainted
}

func (h *emailVerifyHandler) InitiateChallenge(_ context.Context, subject string) (string, error) {
	if h.tainted {
		return taintedChallenge, nil
	}
	random, err := rand.Int(rand.Reader, big.NewInt(999999))
	if err != nil {
		return "", fmt.Errorf("failed to generate verification code (cause: %w)", err)
	}
	code := fmt.Sprintf("%06d", random.Uint64())
	user, err := h.userStore.LookupUser(subject)
	if err != nil {
		return "", err
	}
	userEmail := user.Email.Address
	if userEmail == "" {
		return "", fmt.Errorf("no email defined for user (subject: %s)", subject)
	}
	userName := user.Profile.Name
	err = h.mailer.NewMessage().Subject("Verification code").BodyFromHTMLTemplate(templates.FS, templates.VerficationCodeTemplate, &templates.VerificationCodeData{Code: code}).SendTo(userEmail, userName)
	if err != nil {
		return "", err
	}
	return h.challenge(code), nil
}

func (h *emailVerifyHandler) VerifyRepsonse(_ context.Context, subject string, challenge string, response string) error {
	if challenge == taintedChallenge {
		h.tainted = true
		return errUserNotAuthenticated
	}
	if challenge != h.challenge(response) {
		return fmt.Errorf("invalid email verification code")
	}
	return nil
}

func (h *emailVerifyHandler) challenge(code string) string {
	return string(VerifyMethodEmail) + ":" + code
}

func MockVerifyHandler() VerifyHandler {
	return &mockVerifyHandler{}
}

type mockVerifyHandler struct{}

func (*mockVerifyHandler) Method() VerifyMethod {
	return VerifyMethodNone
}

func (*mockVerifyHandler) Taint() {
	// Nothing to do here
}

func (*mockVerifyHandler) Tainted() bool {
	return false
}

func (*mockVerifyHandler) InitiateChallenge(_ context.Context, _ string) (string, error) {
	return string(VerifyMethodNone), nil
}

func (h *mockVerifyHandler) VerifyRepsonse(_ context.Context, _ string, _ string, _ string) error {
	return nil
}
