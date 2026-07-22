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
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/domain"
)

type UserSessionRequest struct {
	ID         string `db:"id"`
	State      string `db:"state"`
	AuthInfo   []byte `db:"auth_info"`
	CreateTime int64  `db:"create_time"`
}

type authInfoPayload struct {
	Handler string `json:"handler"`
}

func (p *authInfoPayload) Marshal() ([]byte, error) {
	buffer := &bytes.Buffer{}
	err := json.NewEncoder(buffer).Encode(p)
	if err != nil {
		return nil, fmt.Errorf("failed to encode UserSessionRequest AuthInfo (cause: %w)", err)
	}
	return buffer.Bytes(), nil
}

func (usr *UserSessionRequest) ToDomain() (*domain.UserSessionRequest, error) {
	userSessionRequest := &domain.UserSessionRequest{
		ID: usr.ID,
	}
	return userSessionRequest, nil
}

func InsertUserSessionRequest(ctx context.Context, tx *database.Tx, userSessionRequest *domain.UserSessionRequest) (*UserSessionRequest, error) {
	authInfo := &authInfoPayload{
		Handler: userSessionRequest.Handler,
	}
	authInfoBytes, err := authInfo.Marshal()
	if err != nil {
		return nil, err
	}
	r := &UserSessionRequest{
		ID:         database.NewID(),
		State:      string(userSessionRequest.State),
		AuthInfo:   authInfoBytes,
		CreateTime: database.Time2DB(tx.Now()),
	}
	return r, nil
}
