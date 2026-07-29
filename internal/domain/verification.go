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
)

var ErrChallengeResponseMismatch error = errors.New("verification mismatch")

// Verification represents the method used to verify a user's identity during authentication.
type Verification string

const (
	VerificationEmail   Verification = "email"
	VerificationTOTP    Verification = "totp"
	VerificationPasskey Verification = "passkey"
	VerificationSecKey  Verification = "seckey"
)

func (v Verification) String() string {
	return string(v)
}

// IsStrong returns true for verification methods that provide strong (multi-factor) authentication.
func (v Verification) IsStrong() bool {
	return v == VerificationPasskey || v == VerificationSecKey
}

// IsStrongAuth checks whether the named verification method counts as strong authentication.
func IsStrongAuth(verificationName string) bool {
	return Verification(verificationName).IsStrong()
}

type VerificationHandler interface {
	Verification() Verification
	GenerateChallenge(ctx context.Context, user *User) (string, error)
	VerifyResponse(ctx context.Context, challenge, response string) error
}

type VerificationHandlerRegistry interface {
	GetVerificationHandler(verification Verification) VerificationHandler
	ListVerifications(strong bool) []Verification
}
