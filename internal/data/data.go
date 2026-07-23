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

	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/config"
	"github.com/tdrn-org/idpd/internal/crypto"
	"github.com/tdrn-org/idpd/internal/data/model"
	"github.com/tdrn-org/idpd/internal/domain"
)

type Store struct {
	cfg    *config.GeneralConfig
	driver *database.Driver
	logger *slog.Logger
}

func NewStore(driver *database.Driver, name string, cfg *config.GeneralConfig) *Store {
	return &Store{
		cfg:    cfg,
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

func (s *Store) Atomic(ctx context.Context, atomics ...AtomicFunc) error {
	txCtx, tx, err := s.driver.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.RollbackUncommitedTx(txCtx)

	for _, atomic := range atomics {
		err = atomic(txCtx, tx)
		if err != nil {
			return err
		}
	}

	return tx.CommitTx(txCtx)
}

func (s *Store) CurrentTx(ctx context.Context) (*database.Tx, bool) {
	return s.driver.CurrentTx(ctx)
}

func (s *Store) ActiveIntegrityContext(ctx context.Context) (domain.IntegrityContext, error) {
	txCtx, tx, err := s.driver.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.RollbackUncommitedTx(txCtx)

	deleteBefore := tx.Now().Add(-time.Duration(s.cfg.IntegrityContextKeyLifetime))
	err = model.DeleteIntegrityContextKeyByCreateTime(txCtx, tx, deleteBefore)
	if err != nil {
		return nil, err
	}
	inactiveBefore := tx.Now().Add(-time.Duration(s.cfg.IntegrityContextKeyRotation))
	k, err := model.SelectIntegrityContextKey(txCtx, tx)
	if err != nil {
		return nil, err
	}
	if database.DB2Time(k.CreateTime).Before(inactiveBefore) {
		integrityContext, err := crypto.NewNaClSecretBoxContext(nil)
		if err != nil {
			return nil, err
		}
		integrityContextKey := integrityContext.Key()
		k, err = model.InsertIntegrityContextKey(txCtx, tx, &integrityContextKey)
		if err != nil {
			return nil, err
		}
	}
	integrityContext, err := crypto.NewNaClSecretBoxContext(k.ToKey())
	if err != nil {
		return nil, err
	}

	err = tx.CommitTx(txCtx)
	if err != nil {
		return nil, err
	}

	return integrityContext, nil
}

func (s *Store) LookupIntegrityContext(ctx context.Context, keyID string) (domain.IntegrityContext, error) {
	return nil, nil
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
