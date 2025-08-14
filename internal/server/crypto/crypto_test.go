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

package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/server/crypto"
)

func TestAsymetricKey(t *testing.T) {
	keyTypes := []crypto.AsymetricKeyType{
		crypto.AsymetricKeyTypeRSA2048,
		crypto.AsymetricKeyTypeECDSAP256,
	}
	for _, keyType := range keyTypes {
		t.Run(string(keyType), func(t *testing.T) {
			key, err := crypto.NewAsymetricKey(keyType)
			require.NoError(t, err)
			require.Equal(t, keyType, key.KeyType())
		})
	}
}

func TestSymetricKey(t *testing.T) {
	keyTypes := []crypto.SymetricKeyType{
		crypto.SymetricKeyTypeAES256SHA256,
	}
	for _, keyType := range keyTypes {
		t.Run(string(keyType), func(t *testing.T) {
			key, err := crypto.NewSymetricKey(keyType)
			require.NoError(t, err)
			require.Equal(t, keyType, key.KeyType())
			text := "The quick brown fox jumped over the lazy dog"
			ciphertext, err := key.Encrypt(text)
			require.NoError(t, err)
			plaintext, err := key.Decrypt(ciphertext)
			require.NoError(t, err)
			require.Equal(t, text, plaintext)
		})
	}
}
