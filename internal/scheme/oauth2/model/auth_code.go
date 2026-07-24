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

	"github.com/tdrn-org/go-database"
)

type AuthCode struct {
	Code          string `db:"code"`
	AuthRequestID string `db:"auth_request_id"`
}

//go:embed auth_code.insert.sql
var insertAuthCodeSQL string

func InsertAuthCode(ctx context.Context, tx *database.Tx, code, authRequestID string) (*AuthCode, error) {
	c := &AuthCode{
		Code:          code,
		AuthRequestID: authRequestID,
	}
	err := tx.ExecTx(ctx, insertAuthCodeSQL,
		c.Code,
		c.AuthRequestID)
	if err != nil {
		return nil, err
	}
	return c, nil
}

//go:embed auth_code.delete_by_auth_request_id.sql
var deleteAuthCodeByAuthRequestIDSQL string

func DeleteAuthCodeByAuthRequestID(ctx context.Context, tx *database.Tx, authRequestID string) error {
	return tx.ExecTx(ctx, deleteAuthCodeByAuthRequestIDSQL, authRequestID)
}
