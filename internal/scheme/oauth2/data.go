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

package oauth2

import (
	"context"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/crypto"
	"github.com/tdrn-org/idpd/internal/scheme/oauth2/model"
)

func (h *Handler) activeSigningKey(ctx context.Context, algorithm jose.SignatureAlgorithm) (*crypto.JoseSigningKey, error) {
	var signingKey *crypto.JoseSigningKey
	err := h.runtime.DataStore().Atomic(ctx, func(txCtx context.Context, tx *database.Tx) error {
		deleteBefore := tx.Now().Add(-time.Duration(h.cfg.SigningKeyLifetime))
		err := model.DeleteSigningKeyByCreateTime(txCtx, tx, deleteBefore)
		if err != nil {
			return err
		}
		inactiveBefore := tx.Now().Add(-time.Duration(h.cfg.SigningKeyRotation))
		storeSigningKey, err := model.SelectSigningKeyByAlgorithm(txCtx, tx, algorithm)
		if err != nil {
			return err
		}
		if database.DB2Time(storeSigningKey.CreateTime).Before(inactiveBefore) {
			signingKey, err := crypto.NewSigningKey(algorithm)
			if err != nil {
				return err
			}
			storeSigningKey, err = model.InsertSigningKey(txCtx, tx, signingKey)
			if err != nil {
				return err
			}
		}
		signingKey, err = storeSigningKey.ToJoseSigningKey()
		return err
	})
	return signingKey, err
}
