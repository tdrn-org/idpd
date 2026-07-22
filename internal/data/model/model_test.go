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

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/go-database/memory"
	"github.com/tdrn-org/idpd/internal/data/model"
)

func newTestDB(t *testing.T) *database.Driver {
	driver, err := database.Open(memory.NewConfig(model.SqliteSchemaScriptOption))
	require.NoError(t, err)
	from, to, err := driver.UpdateSchema(t.Context())
	require.NoError(t, err)
	require.Equal(t, database.SchemaNone, from)
	require.Equal(t, 1, to)
	return driver
}

func runInTx(t *testing.T, driver *database.Driver, fn func(ctx context.Context, tx *database.Tx)) {
	txCtx, tx, err := driver.BeginTx(t.Context())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, tx.RollbackUncommitedTx(txCtx))
	}()
	fn(txCtx, tx)
	require.NoError(t, tx.CommitTx(txCtx))
}
