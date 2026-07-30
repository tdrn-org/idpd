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
)

type UserSession struct {
	ID             string `db:"id"`
	Login          string `db:"login"`
	Remember       bool   `db:"remember"`
	Verification   string `db:"verification"`
	Terminated     bool   `db:"terminated"`
	CreateTime     int64  `db:"create_time"`
	LastAccessTime int64  `db:"last_access_time"`
}

func (s *UserSession) ToDomain() *domain.UserSession {
	if s == nil {
		return nil
	}
	return &domain.UserSession{
		ID:             s.ID,
		Login:          s.Login,
		Remember:       s.Remember,
		Verification:   domain.Verification(s.Verification),
		Terminated:     s.Terminated,
		CreateTime:     database.DB2Time(s.CreateTime),
		LastAccessTime: database.DB2Time(s.LastAccessTime),
	}
}

//go:embed user_session.insert.sql
var insertUserSessionSQL string

func InsertUserSession(ctx context.Context, tx *database.Tx, userSessionRequest *domain.UserSessionRequest) (*UserSession, error) {
	s := &UserSession{
		ID:             database.NewID(),
		Login:          userSessionRequest.AuthInfo.Login,
		Remember:       userSessionRequest.AuthInfo.Remember,
		Verification:   userSessionRequest.AuthInfo.Verification.String(),
		Terminated:     false,
		CreateTime:     database.Time2DB(tx.Now()),
		LastAccessTime: database.Time2DB(tx.Now()),
	}
	err := tx.ExecTx(ctx, insertUserSessionSQL,
		s.ID,
		s.Login,
		s.Remember,
		s.Verification,
		s.Terminated,
		s.CreateTime,
		s.LastAccessTime)
	if err != nil {
		return nil, err
	}
	return s, nil
}

//go:embed user_session.select_by_id.sql
var selectUserSessionByIDSQL string

func SelectUserSessionByID(ctx context.Context, tx *database.Tx, id string) (*UserSession, error) {
	row, err := tx.QueryRowTx(ctx, selectUserSessionByIDSQL, id)
	if err != nil {
		return nil, err
	}
	s := &UserSession{
		ID: id,
	}
	err = database.ScanRow(row, s, "login", "remember", "verification", "terminated", "create_time", "last_access_time")
	if database.NoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return s, nil
}
