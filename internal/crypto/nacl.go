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

package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/tdrn-org/idpd/internal/domain"
	"golang.org/x/crypto/nacl/secretbox"
)

// NewIntegrityKey generates a new random 32-byte key for NaCl SecretBox.
func NewIntegrityKey() ([32]byte, error) {
	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return key, fmt.Errorf("failed to generate integrity key (cause: %w)", err)
	}
	return key, nil
}

// NaClSecretBoxContext implements domain.IntegrityContext using NaCl SecretBox
// (XSalsa20-Poly1305). This provides both encryption and authentication in a
// single AEAD operation — no separate signature is needed.
type NaClSecretBoxContext struct {
	key   [32]byte
	keyID string
}

// NewNaClSecretBoxContext creates a new context backed by the given key.
func NewNaClSecretBoxContext(key [32]byte, keyID string) *NaClSecretBoxContext {
	return &NaClSecretBoxContext{
		key:   key,
		keyID: keyID,
	}
}

// Secure encrypts and authenticates the payload.
// The nonce is generated randomly and prepended to the ciphertext.
// Signature is nil — NaCl SecretBox provides authentication internally.
func (c *NaClSecretBoxContext) Secure(payload []byte) (*domain.IntegrityPayload, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce (cause: %w)", err)
	}

	// secretbox.Seal appends the encrypted payload to the (empty) nonce slice.
	// Result layout: [nonce:24][encrypted:len(payload)+Overhead]
	ciphertext := secretbox.Seal(nonce[:], payload, &nonce, &c.key)

	return &domain.IntegrityPayload{
		CipherText: ciphertext,
		Signature:  nil, // AEAD — no detached signature needed
		KeyID:      c.keyID,
	}, nil
}

// VerifyAndDecrypt verifies the integrity and decrypts the payload.
// The nonce is extracted from the first 24 bytes of CipherText.
func (c *NaClSecretBoxContext) VerifyAndDecrypt(secured *domain.IntegrityPayload) ([]byte, error) {
	if len(secured.CipherText) < 24 {
		return nil, domain.ErrIntegrityContextIntegrityViolated
	}

	var nonce [24]byte
	copy(nonce[:], secured.CipherText[:24])
	ciphertext := secured.CipherText[24:]

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &c.key)
	if !ok {
		return nil, domain.ErrIntegrityContextIntegrityViolated
	}

	return plaintext, nil
}
