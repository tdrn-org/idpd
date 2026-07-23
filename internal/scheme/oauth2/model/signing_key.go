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

	"github.com/go-jose/go-jose/v4"
	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/crypto"
)

type SigningKey struct {
	ID         string `db:"id"`
	Algorithm  string `db:"algorithm"`
	PrivateKey []byte `db:"private_key"`
	CreateTime int64  `db:"create_time"`
}

func (k *SigningKey) ToJoseSigningKey() (*crypto.JoseSigningKey, error) {
	if k == nil {
		return nil, nil
	}
	algorithm := jose.SignatureAlgorithm(k.Algorithm)
	key, err := crypto.UnmarshalSigningKey(algorithm, k.PrivateKey)
	if err != nil {
		return nil, err
	}
	signingKey := &crypto.JoseSigningKey{
		ID:         k.ID,
		Algorithm:  jose.SignatureAlgorithm(k.Algorithm),
		Key:        key,
		CreateTime: database.DB2Time(k.CreateTime),
	}
	return signingKey, nil
}

//go:embed signing_key.insert.sql
var insertSigningKeySQL string

func InsertSigningKey(ctx context.Context, tx *database.Tx, signingKey *crypto.JoseSigningKey) (*SigningKey, error) {
	algorithm, privateKey, err := crypto.MarshalSigningKey(signingKey)
	if err != nil {
		return nil, err
	}
	k := &SigningKey{
		ID:         database.NewID(),
		Algorithm:  string(algorithm),
		PrivateKey: privateKey,
		CreateTime: database.Time2DB(tx.Now()),
	}
	err = tx.ExecTx(ctx, insertSigningKeySQL, k.ID, k.Algorithm, k.PrivateKey, k.CreateTime)
	if err != nil {
		return nil, err
	}
	signingKey.ID, signingKey.CreateTime = k.ID, database.DB2Time(k.CreateTime)
	return k, nil
}

//go:embed signing_key.select_by_algorithm.sql
var selectSigningKeyByAlgorithmSQL string

func SelectSigningKeyByAlgorithm(ctx context.Context, tx *database.Tx, algorithm jose.SignatureAlgorithm) (*SigningKey, error) {
	var k *SigningKey
	row, err := tx.QueryRowTx(ctx, selectSigningKeyByAlgorithmSQL, algorithm)
	if err != nil {
		return nil, err
	}
	k = &SigningKey{
		Algorithm: string(algorithm),
	}
	err = database.ScanRow(row, k, "id", "private_key", "create_time")
	if database.NoRows(err) {
		k = nil
	} else if err != nil {
		return nil, err
	}
	return k, nil
}

//go:embed signing_key.delete_by_create_time.sql
var deleteSigningKeyByCreateTimeSQL string

func DeleteSigningKeyByCreateTime(ctx context.Context, tx *database.Tx, before time.Time) error {
	return tx.ExecTx(ctx, deleteSigningKeyByCreateTimeSQL, database.Time2DB(before))
}
