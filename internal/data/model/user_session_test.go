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

package model_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/data/model"
	"github.com/tdrn-org/idpd/internal/domain"
)

func TestUserSession(t *testing.T) {
	driver := newTestDB(t)

	userSessionRequest := &domain.UserSessionRequest{
		IC: newNoopIntegrityContext(),
		AuthInfo: domain.UserSessionRequestAuthInfo{
			Handler:      t.Name(),
			Login:        "test",
			Verification: domain.VerificationEmail,
		},
	}

	// Insert
	var s1 *model.UserSession
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		s, err := model.InsertUserSession(ctx, tx, userSessionRequest)
		require.NoError(t, err)
		require.NotNil(t, s)
		s1 = s
	})

	// Select
	var s2 *model.UserSession
	runInTx(t, driver, func(ctx context.Context, tx *database.Tx) {
		s, err := model.SelectUserSessionByID(ctx, tx, s1.ID)
		require.NoError(t, err)
		require.Equal(t, s1, s)
		s2 = s
	})
	_ = s2
}
