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

// IntegrityPayload carries the secured representation of a domain object.
// CipherText + Signature + KeyID form the result of the Secure() operation
// and are persisted together (e.g. in UserSessionRequest.AuthInfo or
// dedicated DB columns).
type IntegrityPayload struct {
	// KeyID identifies the key and algorithm used (e.g. "nacl-secretbox:v1:<uuid>").
	KeyID string `json:"key_id"`

	// CipherText is the encrypted payload.
	CipherText []byte `json:"cipher_text"`

	// Signature is the detached signature (nil for AEAD schemes like NaCl SecretBox).
	Signature []byte `json:"signature,omitempty"`
}
