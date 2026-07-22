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

	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/domain"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type AuthRequest struct {
	ID string `db:"id"`
}

func (r *AuthRequest) OpAuthRequest() op.AuthRequest {
	return nil
}

func InsertAuthRequest(ctx context.Context, tx *database.Tx, userSessionRequest *domain.UserSessionRequest, oidcAuthRequest *oidc.AuthRequest) (*AuthRequest, error) {
	r := &AuthRequest{
		ID: database.NewID(),
	}
	return r, nil
}
