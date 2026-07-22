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
	"log/slog"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/crypto"
	"github.com/tdrn-org/idpd/internal/data/model"
	"github.com/tdrn-org/idpd/internal/domain"
)

type Store struct {
	driver *database.Driver
	logger *slog.Logger
}

func NewStore(driver *database.Driver, name string) *Store {
	return &Store{
		driver: driver,
		logger: slog.With(slog.String("name", name)),
	}
}

func (s *Store) Ping(ctx context.Context) error {
	return s.driver.Ping(ctx)
}

func (s *Store) Close() error {
	return s.driver.Close()
}

type AtomicFunc func(txCtx context.Context, tx *database.Tx) error

func (s *Store) Atomic(ctx context.Context, atomic AtomicFunc) error {
	txCtx, tx, err := s.driver.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.RollbackUncommitedTx(txCtx)

	err = atomic(txCtx, tx)
	if err != nil {
		return err
	}

	return tx.CommitTx(txCtx)
}

func (s *Store) CurrentTx(ctx context.Context) (*database.Tx, bool) {
	return s.driver.CurrentTx(ctx)
}

func (s *Store) CreateUserSessionRequest(ctx context.Context, handler string) (*domain.UserSessionRequest, error) {
	return nil, nil
}

func (s *Store) SelectUserSessionRequestByID(ctx context.Context, id string) (*domain.UserSessionRequest, error) {
	return nil, nil
}

func (s *Store) UpdateUserSessionRequest(ctx context.Context, request *domain.UserSessionRequest) error {
	return nil
}

func (s *Store) GetSigningKey(ctx context.Context, algorithm jose.SignatureAlgorithm, activeDuration, lifetimeDuration time.Duration) (*domain.SigningKey, error) {
	txCtx, tx, err := s.driver.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.RollbackUncommitedTx(txCtx)

	deleteBefore := tx.Now().Add(-lifetimeDuration)
	err = model.DeleteSigningKeyByCreateTime(txCtx, s.driver, deleteBefore)
	if err != nil {
		return nil, err
	}
	inactiveBefore := tx.Now().Add(-activeDuration)
	storeSigningKey, err := model.SelectSigningKeyByAlgorithm(txCtx, s.driver, algorithm)
	if err != nil {
		return nil, err
	}
	if database.DB2Time(storeSigningKey.CreateTime).Before(inactiveBefore) {
		signingKey, err := crypto.NewSigningKey(algorithm)
		if err != nil {
			return nil, err
		}
		storeSigningKey, err = model.InsertSigningKey(txCtx, s.driver, signingKey)
		if err != nil {
			return nil, err
		}
	}
	signingKey, err := storeSigningKey.ToDomain()
	if err != nil {
		return nil, err
	}

	err = tx.CommitTx(txCtx)
	if err != nil {
		return nil, err
	}

	return signingKey, nil
}
