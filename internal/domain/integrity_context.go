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

var ErrIntegrityContextKeyNotFound error = errors.New("integrity context key not found")
var ErrIntegrityContextIntegrityViolated error = errors.New("data integrity violated")

// IntegrityContext encapsulates the functions needed to save and restore state
// information while ensuring their integrity.
type IntegrityContext interface {
	// KeyID returns the key ID of this instance.
	KeyID() string

	// Secure encrypts and signs the payload, returning the secured representation.
	Secure(payload []byte) (*IntegrityPayload, error)

	// VerifyAndDecrypt verifies the integrity of the secured payload and
	// returns the original plaintext.
	VerifyAndDecrypt(secured *IntegrityPayload) ([]byte, error)
}

// IntegrityContextStore provides access to IntegrityContext instances.
// Implemented by data.Store.
type IntegrityContextStore interface {
	// ActiveIntegrityContext returns the context backed by the newest key (for Secure operations).
	ActiveIntegrityContext(ctx context.Context) (IntegrityContext, error)

	// LookupIntegrityContext returns the context for a specific keyID (for VerifyAndDecrypt).
	LookupIntegrityContext(ctx context.Context, keyID string) (IntegrityContext, error)
}
