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

package model_test

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/crypto"
	"github.com/tdrn-org/idpd/internal/data/model"
)

func TestSigningKey(t *testing.T) {
	driver := newTestDB(t)

	algorithm := jose.RS256
	signingKey, err := crypto.NewSigningKey(algorithm)
	require.NoError(t, err)

	// Select (no signing key)
	k1, err := model.SelectSigningKeyByAlgorithm(t.Context(), driver, algorithm)
	require.NoError(t, err)
	require.Nil(t, k1)

	// Insert
	k1, err = model.InsertSigningKey(t.Context(), driver, signingKey)
	require.NoError(t, err)
	require.Equal(t, string(algorithm), k1.Algorithm)

	// Select (existing signing key)
	k2, err := model.SelectSigningKeyByAlgorithm(t.Context(), driver, algorithm)
	require.NoError(t, err)
	require.Equal(t, k1, k2)

	// Delete
	err = model.DeleteSigningKeyByCreateTime(t.Context(), driver, time.Now())
	require.NoError(t, err)

	// Select (no signing key)
	signingKey3, err := model.SelectSigningKeyByAlgorithm(t.Context(), driver, algorithm)
	require.NoError(t, err)
	require.Nil(t, signingKey3)
}
