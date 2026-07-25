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

package forward

import (
	"context"

	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/scheme/forward/model"
)

func (h *Handler) createAuthRequest(ctx context.Context, redirectURL string) (*model.AuthRequest, error) {
	var authRequest *model.AuthRequest
	err := h.runtime.DataStore().Atomic(ctx, func(txCtx context.Context, tx *database.Tx) error {
		userSessionRequest, err := h.runtime.DataStore().CreateUserSessionRequest(txCtx, h.Name().String(), "", h.runtime.DemoUser())
		if err != nil {
			return err
		}
		r, err := model.InsertAuthRequest(txCtx, tx, userSessionRequest, redirectURL)
		if err != nil {
			return err
		}
		authRequest = r
		return nil
	})
	return authRequest, err
}
