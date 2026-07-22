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
	"bytes"
	"testing"

	"github.com/tdrn-org/idpd/internal/domain"
)

func TestNaClSecretBoxContextRoundTrip(t *testing.T) {
	key, err := NewIntegrityKey()
	if err != nil {
		t.Fatalf("NewIntegrityKey failed: %v", err)
	}

	ctx := NewNaClSecretBoxContext(key, "nacl-secretbox:v1:test-key")
	payload := []byte("Hello, idpd!")

	// Encrypt
	secured, err := ctx.Secure(payload)
	if err != nil {
		t.Fatalf("Secure failed: %v", err)
	}

	// Verify structure
	if len(secured.CipherText) < 24 {
		t.Fatal("CipherText too short — missing nonce")
	}
	if secured.Signature != nil {
		t.Fatal("Expected nil Signature for AEAD scheme")
	}
	if secured.KeyID != "nacl-secretbox:v1:test-key" {
		t.Fatalf("KeyID mismatch: got %q", secured.KeyID)
	}

	// Decrypt
	plaintext, err := ctx.VerifyAndDecrypt(secured)
	if err != nil {
		t.Fatalf("VerifyAndDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, payload) {
		t.Fatalf("Round-trip mismatch: got %q, want %q", plaintext, payload)
	}
}

func TestNaClSecretBoxContextTampered(t *testing.T) {
	key, err := NewIntegrityKey()
	if err != nil {
		t.Fatalf("NewIntegrityKey failed: %v", err)
	}

	ctx := NewNaClSecretBoxContext(key, "nacl-secretbox:v1:test-key")
	payload := []byte("tamper me")

	secured, err := ctx.Secure(payload)
	if err != nil {
		t.Fatalf("Secure failed: %v", err)
	}

	// Flip a byte in the ciphertext (after nonce)
	tampered := &domain.IntegrityPayload{
		CipherText: make([]byte, len(secured.CipherText)),
		Signature:  nil,
		KeyID:      secured.KeyID,
	}
	copy(tampered.CipherText, secured.CipherText)
	tampered.CipherText[30] ^= 0x01

	_, err = ctx.VerifyAndDecrypt(tampered)
	if err != domain.ErrIntegrityContextIntegrityViolated {
		t.Fatalf("Expected ErrIntegrityContextIntegrityViolated, got %v", err)
	}
}

func TestNaClSecretBoxContextWrongKey(t *testing.T) {
	key1, _ := NewIntegrityKey()
	key2, _ := NewIntegrityKey()

	ctx1 := NewNaClSecretBoxContext(key1, "key-1")
	ctx2 := NewNaClSecretBoxContext(key2, "key-1")

	secured, err := ctx1.Secure([]byte("secret"))
	if err != nil {
		t.Fatalf("Secure failed: %v", err)
	}

	_, err = ctx2.VerifyAndDecrypt(secured)
	if err != domain.ErrIntegrityContextIntegrityViolated {
		t.Fatalf("Expected ErrIntegrityContextIntegrityViolated with wrong key, got %v", err)
	}
}

func TestNaClSecretBoxContextTruncated(t *testing.T) {
	key, _ := NewIntegrityKey()
	ctx := NewNaClSecretBoxContext(key, "test")

	_, err := ctx.VerifyAndDecrypt(&domain.IntegrityPayload{
		CipherText: []byte("too-short"),
	})
	if err != domain.ErrIntegrityContextIntegrityViolated {
		t.Fatalf("Expected ErrIntegrityContextIntegrityViolated, got %v", err)
	}
}
