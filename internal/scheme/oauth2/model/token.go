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
	"github.com/zitadel/oidc/v3/pkg/op"
)

type Token struct {
	ID             string `db:"id"`
	ClientID       string `db:"client_id"`
	Subject        string `db:"subject"`
	RefreshTokenID string `db:"refresh_token_id"`
	CreateTime     int64  `db:"create_time"`
	ExpiryTime     int64  `db:"expiry_time"`
}

//go:embed token.insert.sql
var insertTokenSQL string

func InsertTokenFromAuthRequest(ctx context.Context, tx *database.Tx, request op.AuthRequest, refreshTokenID string, lifetimeDuration time.Duration) (*Token, error) {
	t := &Token{
		ID:             database.NewID(),
		ClientID:       request.GetClientID(),
		Subject:        request.GetSubject(),
		RefreshTokenID: refreshTokenID,
		CreateTime:     database.Time2DB(tx.Now()),
		ExpiryTime:     database.Time2DB(tx.Now().Add(lifetimeDuration)),
	}
	err := tx.ExecTx(ctx, insertTokenSQL,
		t.ID,
		t.ClientID,
		t.Subject,
		t.RefreshTokenID,
		t.CreateTime,
		t.ExpiryTime)
	if err != nil {
		return nil, err
	}
	return t, nil
}
