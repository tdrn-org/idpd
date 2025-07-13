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

package server_test

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/server"
)

func TestSigningKeyForAlgorithm(t *testing.T) {
	algorithms := []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256}
	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			now := time.Now()
			passivation := now.Add(time.Minute).UnixMicro()
			expiration := now.Add(5 * time.Minute).UnixMicro()
			signatureKey, err := server.SigningKeyForAlgorithm(algorithm, passivation, expiration)
			require.NoError(t, err)
			require.NotNil(t, signatureKey)
			require.NotEmpty(t, signatureKey.ID)
			require.Equal(t, string(algorithm), signatureKey.Algorithm)
			require.NotEmpty(t, signatureKey.PrivateKey)
			require.NotEmpty(t, signatureKey.PublicKey)
			require.Equal(t, expiration, signatureKey.Expiration)
		})
	}
}
