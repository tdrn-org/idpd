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
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AuthRequest struct {
	ID                   string `db:"id"`
	UserSessionRequestID string `db:"user_session_request_id"`
	OIDCAuthRequest      []byte `db:"oidc_auth_request"`
	CreateTime           int64  `db:"create_time"`
}

//go:embed auth_request.insert.sql
var insertAuthRequestSQL string

func InsertAuthRequest(ctx context.Context, tx *database.Tx, userSessionRequest *domain.UserSessionRequest, oidcAuthRequest *oidc.AuthRequest) (*AuthRequest, error) {
	oidcAuthRequestBytes, err := encoding.MarshalJSONPayload(oidcAuthRequest)
	if err != nil {
		return nil, err
	}
	r := &AuthRequest{
		ID:                   database.NewID(),
		UserSessionRequestID: userSessionRequest.ID,
		OIDCAuthRequest:      oidcAuthRequestBytes,
		CreateTime:           database.Time2DB(tx.Now()),
	}
	err = tx.ExecTx(ctx, insertAuthRequestSQL,
		r.ID,
		r.UserSessionRequestID,
		r.OIDCAuthRequest,
		r.CreateTime)
	if err != nil {
		return nil, err
	}
	return r, nil
}

//go:embed auth_request.select_by_id.sql
var selectAuthRequestByIDSQL string

func SelectAuthRequestByID(ctx context.Context, tx *database.Tx, id string) (*AuthRequest, *oidc.AuthRequest, error) {
	row, err := tx.QueryRowTx(ctx, selectAuthRequestByIDSQL, id)
	if err != nil {
		return nil, nil, err
	}
	r := &AuthRequest{
		ID: id,
	}
	err = database.ScanRow(row, r, "user_session_request_id", "oidc_auth_request", "create_time")
	if database.NoRows(err) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}
	oidcAuthRequest := &oidc.AuthRequest{}
	err = encoding.UnmarshalJSONPayload(oidcAuthRequest, r.OIDCAuthRequest)
	if err != nil {
		return nil, nil, err
	}
	return r, oidcAuthRequest, nil
}

//go:embed auth_request.select_by_code.sql
var selectAuthRequestByCodeSQL string

func SelectAuthRequestByCode(ctx context.Context, tx *database.Tx, code string) (*AuthRequest, *oidc.AuthRequest, error) {
	row, err := tx.QueryRowTx(ctx, selectAuthRequestByCodeSQL, code)
	if err != nil {
		return nil, nil, err
	}
	r := &AuthRequest{}
	err = database.ScanRow(row, r, "id", "user_session_request_id", "oidc_auth_request", "create_time")
	if database.NoRows(err) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}
	oidcAuthRequest := &oidc.AuthRequest{}
	err = encoding.UnmarshalJSONPayload(oidcAuthRequest, r.OIDCAuthRequest)
	if err != nil {
		return nil, nil, err
	}
	return r, oidcAuthRequest, nil
}

//go:embed auth_request.delete_by_id.sql
var deleteAuthRequestByIDSQL string

func DeleteAuthRequestByID(ctx context.Context, tx *database.Tx, id string) error {
	return tx.ExecTx(ctx, deleteAuthCodeByAuthRequestIDSQL, id)
}
