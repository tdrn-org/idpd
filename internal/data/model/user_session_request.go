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
	"github.com/tdrn-org/idpd/internal/domain"
	"github.com/tdrn-org/idpd/internal/encoding"
)

type UserSessionRequest struct {
	ID         string `db:"id"`
	AuthInfo   []byte `db:"auth_info"`
	CreateTime int64  `db:"create_time"`
}

func (r *UserSessionRequest) ToDomain(ctx context.Context, icStore domain.IntegrityContextStore) (*domain.UserSessionRequest, error) {
	authInfoPayload := &domain.IntegrityPayload{}
	err := encoding.UnmarshalJSONPayload(authInfoPayload, r.AuthInfo)
	if err != nil {
		return nil, err
	}
	ic, err := icStore.LookupIntegrityContext(ctx, authInfoPayload.KeyID)
	if err != nil {
		return nil, err
	}
	authInfoBytes, err := ic.VerifyAndDecrypt(authInfoPayload)
	if err != nil {
		return nil, err
	}
	userSessionRequest := &domain.UserSessionRequest{
		ID:         r.ID,
		IC:         ic,
		CreateTime: database.DB2Time(r.CreateTime),
	}
	err = encoding.UnmarshalJSONPayload(&userSessionRequest.AuthInfo, authInfoBytes)
	if err != nil {
		return nil, err
	}
	return userSessionRequest, nil
}

//go:embed user_session_request.insert.sql
var insertUserSessionRequestSQL string

func InsertUserSessionRequest(ctx context.Context, tx *database.Tx, userSessionRequest *domain.UserSessionRequest) (*UserSessionRequest, error) {
	authInfoBytes, err := encoding.MarshalJSONPayload(&userSessionRequest.AuthInfo)
	if err != nil {
		return nil, err
	}
	authInfoPayload, err := userSessionRequest.IC.Secure(authInfoBytes)
	if err != nil {
		return nil, err
	}
	authInfoBytes, err = encoding.MarshalJSONPayload(authInfoPayload)
	if err != nil {
		return nil, err
	}
	r := &UserSessionRequest{
		ID:         database.NewID(),
		AuthInfo:   authInfoBytes,
		CreateTime: database.Time2DB(tx.Now()),
	}
	err = tx.ExecTx(ctx, insertUserSessionRequestSQL,
		r.ID,
		r.AuthInfo,
		r.CreateTime)
	if err != nil {
		return nil, err
	}
	userSessionRequest.ID, userSessionRequest.CreateTime = r.ID, database.DB2Time(r.CreateTime)
	return r, nil
}

//go:embed user_session_request.select_by_id.sql
var selectUserSessionRequestByIDSQL string

func SelectUserSessionRequestByID(ctx context.Context, tx *database.Tx, id string) (*UserSessionRequest, error) {
	r := &UserSessionRequest{
		ID: id,
	}
	row, err := tx.QueryRowTx(ctx, selectUserSessionRequestByIDSQL, id)
	if err != nil {
		return nil, err
	}
	err = database.ScanRow(row, r, "auth_info", "create_time")
	if database.NoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return r, nil
}
