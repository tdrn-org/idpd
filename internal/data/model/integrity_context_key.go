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

package model

import (
	"context"
	_ "embed"
	"time"

	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/crypto"
)

type IntegrityContextKey struct {
	ID         string `db:"id"`
	Secret     []byte `db:"secret"`
	CreateTime int64  `db:"create_time"`
}

func (k *IntegrityContextKey) ToKey() *crypto.Key {
	return &crypto.Key{
		ID:     crypto.KeyID(k.ID),
		Secret: k.Secret,
	}
}

//go:embed integrity_context_key.insert.sql
var insertIntegrityContextKeySQL string

func InsertIntegrityContextKey(ctx context.Context, tx *database.Tx, key *crypto.Key) (*IntegrityContextKey, error) {
	k := &IntegrityContextKey{
		ID:         string(key.ID),
		Secret:     key.Secret,
		CreateTime: database.Time2DB(tx.Now()),
	}
	err := tx.ExecTx(ctx, insertIntegrityContextKeySQL,
		k.ID,
		k.Secret,
		k.CreateTime)
	if err != nil {
		return nil, err
	}
	return k, nil
}

//go:embed integrity_context_key.select.sql
var selectIntegrityContextKeySQL string

func SelectIntegrityContextKey(ctx context.Context, tx *database.Tx) (*IntegrityContextKey, error) {
	var k *IntegrityContextKey
	row, err := tx.QueryRowTx(ctx, selectIntegrityContextKeySQL)
	if err != nil {
		return nil, err
	}
	k = &IntegrityContextKey{}
	err = database.ScanRow(row, k, "id", "secret", "create_time")
	if database.NoRows(err) {
		k = nil
	} else if err != nil {
		return nil, err
	}
	return k, nil
}

//go:embed integrity_context_key.select_by_id.sql
var selectIntegrityContextKeyByIDSQL string

func SelectIntegrityContextKeyByID(ctx context.Context, tx *database.Tx, id string) (*IntegrityContextKey, error) {
	var k *IntegrityContextKey
	row, err := tx.QueryRowTx(ctx, selectIntegrityContextKeyByIDSQL, id)
	if err != nil {
		return nil, err
	}
	k = &IntegrityContextKey{
		ID: id,
	}
	err = database.ScanRow(row, k, "secret", "create_time")
	if database.NoRows(err) {
		k = nil
	} else if err != nil {
		return nil, err
	}
	return k, nil
}

//go:embed integrity_context_key.delete_by_create_time.sql
var deleteIntegrityContextKeyByCreateTimeSQL string

func DeleteIntegrityContextKeyByCreateTime(ctx context.Context, tx *database.Tx, before time.Time) error {
	return tx.ExecTx(ctx, deleteIntegrityContextKeyByCreateTimeSQL, database.Time2DB(before))
}
