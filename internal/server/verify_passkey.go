/*
 * Copyright 2025 Holger de Carne
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

package server

import (
	"context"

	"github.com/tdrn-org/idpd/internal/server/database"
)

type PasskeyVerifyHandler struct {
	database            database.Driver
	requestVerification bool
	tainted             bool
}

func NewPasskeyVerifyHandler(database database.Driver, requestVerification bool) *PasskeyVerifyHandler {
	return &PasskeyVerifyHandler{
		database:            database,
		requestVerification: requestVerification,
	}
}

func (*PasskeyVerifyHandler) Method() VerifyMethod {
	return VerifyMethodPasskey
}

func (h *PasskeyVerifyHandler) Taint() {
	h.tainted = true
}

func (h *PasskeyVerifyHandler) Tainted() bool {
	return h.tainted
}

func (h *PasskeyVerifyHandler) GenerateChallenge(ctx context.Context, subject string) (string, error) {
	if h.tainted {
		return taintedChallenge, nil
	}
	return string(VerifyMethodPasskey), nil
}

func (h *PasskeyVerifyHandler) VerifyResponse(ctx context.Context, subject string, challenge string, response string) (bool, error) {
	if challenge == taintedChallenge {
		h.tainted = true
		return false, nil
	}
	if challenge != string(VerifyMethodPasskey) {
		return false, nil
	}
	userVerificationLog := ctx.Value(h).(*database.UserVerificationLog)
	_, err := h.database.InsertOrUpdateUserVerificationLog(ctx, userVerificationLog)
	return true, err
}
