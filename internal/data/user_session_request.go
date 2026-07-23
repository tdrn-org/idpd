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

package data

import (
	"context"

	"github.com/tdrn-org/idpd/internal/data/model"
	"github.com/tdrn-org/idpd/internal/domain"
)

func (s *Store) CreateUserSessionRequest(ctx context.Context, handler string) (*domain.UserSessionRequest, error) {
	ic, err := s.ActiveIntegrityContext(ctx)
	if err != nil {
		return nil, err
	}
	userSessionRequest := &domain.UserSessionRequest{
		IC: ic,
		AuthInfo: domain.UserSessionRequestAuthInfo{
			Handler: handler,
			State:   domain.UserSessionRequestStateCreated,
		},
	}

	txCtx, tx, err := s.driver.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.RollbackUncommitedTx(txCtx)

	_, err = model.InsertUserSessionRequest(txCtx, tx, userSessionRequest)
	if err != nil {
		return nil, err
	}

	err = tx.CommitTx(txCtx)
	if err != nil {
		return nil, err
	}

	return userSessionRequest, nil
}

func (s *Store) GetUserSessionRequest(ctx context.Context, id string) (*domain.UserSessionRequest, error) {
	txCtx, tx, err := s.driver.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.RollbackUncommitedTx(txCtx)

	r, err := model.SelectUserSessionRequestByID(txCtx, tx, id)
	if err != nil {
		return nil, err
	}
	var userSessionRequest *domain.UserSessionRequest
	if r != nil {
		userSessionRequest, err = r.ToDomain(ctx, s)
		if err != nil {
			return nil, err
		}
	}

	err = tx.CommitTx(txCtx)
	if err != nil {
		return nil, err
	}

	return userSessionRequest, nil
}

func (s *Store) UpdateUserSessionRequest(ctx context.Context, request *domain.UserSessionRequest) error {
	return nil
}
