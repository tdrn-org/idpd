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

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/crypto"
	"github.com/tdrn-org/idpd/internal/data/model"
)

func TestIntegrityContextKey(t *testing.T) {
	driver := newTestDB(t)

	cryptoKeySecret, err := crypto.Rand32()
	require.NoError(t, err)
	cryptoKey := &crypto.Key{
		ID:     crypto.KeyID(crypto.NewKeyID(t.Name())),
		Secret: cryptoKeySecret[:],
	}

	// Select (no keys)
	var k1 *model.IntegrityContextKey
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		k1, err = model.SelectIntegrityContextKey(ctx, tx)
		require.NoError(t, err)
		require.Nil(t, k1)
	})

	// Insert
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		k1, err = model.InsertIntegrityContextKey(ctx, tx, cryptoKey)
		require.NoError(t, err)
		require.NotNil(t, k1)
	})

	// Select by ID (existing key)
	var k2 *model.IntegrityContextKey
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		k2, err = model.SelectIntegrityContextKeyByID(ctx, tx, k1.ID)
		require.NoError(t, err)
		require.Equal(t, k1, k2)
	})

	// Select latest (existing key)
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		k2, err = model.SelectIntegrityContextKey(ctx, tx)
		require.NoError(t, err)
		require.Equal(t, k1, k2)
	})

	// Delete (by create time)
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		err := model.DeleteIntegrityContextKeyByCreateTime(ctx, tx, time.Now())
		require.NoError(t, err)
	})

	// Select (no keys)
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		k1, err = model.SelectIntegrityContextKey(ctx, tx)
		require.NoError(t, err)
		require.Nil(t, k1)
	})
}
