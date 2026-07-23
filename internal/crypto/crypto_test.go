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

package crypto_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/crypto"
)

func TestSigningKey(t *testing.T) {
	algorithms := []jose.SignatureAlgorithm{
		jose.HS256,
		jose.HS384,
		jose.HS512,
		jose.RS256,
		jose.RS384,
		jose.RS512,
		jose.PS256,
		jose.PS384,
		jose.PS512,
		jose.ES256,
		jose.ES384,
		jose.ES512,
		jose.EdDSA,
	}
	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			// New
			signingKey, err := crypto.NewSigningKey(algorithm)
			require.NoError(t, err)
			require.Equal(t, algorithm, signingKey.Algorithm)
			// Marshal
			algorithm2, encoded, err := signingKey.MarshalSigningKey()
			require.NoError(t, err)
			// Unmarshal
			signingKey2, err := crypto.UnmarshalSigningKey(algorithm2, encoded)
			require.NoError(t, err)
			require.Equal(t, signingKey, signingKey2)
		})
	}
}
