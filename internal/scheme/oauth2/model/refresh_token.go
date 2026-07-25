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
)

type RefreshToken struct {
	ID            string `db:"id"`
	AccessTokenID string `db:"access_token_id"`
	CreateTime    int64  `db:"create_time"`
	ExpiryTime    int64  `db:"expiry_time"`
}

//go:embed refresh_token.insert.sql
var insertRefreshTokenSQL string

func InsertRefreshToken(ctx context.Context, tx *database.Tx, accessTokenID string, lifetimeDuration time.Duration) (*RefreshToken, error) {
	t := &RefreshToken{
		ID:            database.NewID(),
		AccessTokenID: accessTokenID,
		CreateTime:    database.Time2DB(tx.Now()),
		ExpiryTime:    database.Time2DB(tx.Now().Add(lifetimeDuration)),
	}
	err := tx.ExecTx(ctx, insertRefreshTokenSQL,
		t.ID,
		t.AccessTokenID,
		t.CreateTime,
		t.ExpiryTime)
	if err != nil {
		return nil, err
	}
	return t, nil
}

//go:embed refresh_token.delete_by_id.sql
var deleteRefreshTokenSQL string

func DeleteRefreshTokenByID(ctx context.Context, tx *database.Tx, id string) error {
	return tx.ExecTx(ctx, deleteRefreshTokenSQL, id)
}
