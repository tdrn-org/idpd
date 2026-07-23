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

	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/config"
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
