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
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/crypto"
	"github.com/tdrn-org/idpd/internal/data/model"
)

func TestSigningKey(t *testing.T) {
	driver := newTestDB(t)

	algorithm := jose.RS256
	signingKey, err := crypto.NewSigningKey(algorithm)
	require.NoError(t, err)

	// Select (no signing key)
	var k1 *model.SigningKey
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		k1, err = model.SelectSigningKeyByAlgorithm(ctx, tx, algorithm)
		require.NoError(t, err)
		require.Nil(t, k1)
	})

	// Insert
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		k1, err = model.InsertSigningKey(ctx, tx, signingKey)
		require.NoError(t, err)
		require.Equal(t, string(algorithm), k1.Algorithm)
	})

	// Select (existing signing key)
	var k2 *model.SigningKey
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		k2, err = model.SelectSigningKeyByAlgorithm(ctx, tx, algorithm)
		require.NoError(t, err)
		require.Equal(t, k1, k2)
	})

	// Delete
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		err = model.DeleteSigningKeyByCreateTime(ctx, tx, time.Now())
		require.NoError(t, err)
	})

	// Select (no signing key)
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		signingKey3, err := model.SelectSigningKeyByAlgorithm(ctx, tx, algorithm)
		require.NoError(t, err)
		require.Nil(t, signingKey3)
	})
}
