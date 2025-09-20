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
	"github.com/tdrn-org/idpd/internal/server/totp"
)

type TOTPVerifyHandler struct {
	totpProvider        *totp.Provider
	database            database.Driver
	requestVerification bool
	tainted             bool
}

func NewTOTPVerifyHandler(totpProvider *totp.Provider, database database.Driver, requestVerification bool) *TOTPVerifyHandler {
	return &TOTPVerifyHandler{
		totpProvider:        totpProvider,
		database:            database,
		requestVerification: requestVerification,
	}
}

func (*TOTPVerifyHandler) Method() VerifyMethod {
	return VerifyMethodTOTP
}

func (h *TOTPVerifyHandler) Taint() {
	h.tainted = true
}

func (h *TOTPVerifyHandler) Tainted() bool {
	return h.tainted
}

func (h *TOTPVerifyHandler) GenerateChallenge(ctx context.Context, subject string) (string, error) {
	if h.tainted {
		return taintedChallenge, nil
	}
	return string(VerifyMethodTOTP), nil
}

func (h *TOTPVerifyHandler) VerifyResponse(ctx context.Context, subject string, challenge string, response string) (bool, error) {
	if challenge == taintedChallenge {
		h.tainted = true
		return false, nil
	}
	if challenge != string(VerifyMethodTOTP) {
		return false, nil
	}
	var secret string
	if h.requestVerification {
		registrationRequest, err := h.database.SelectUserTOTPRegistrationRequest(ctx, subject)
		if err != nil {
			return false, err
		}
		secret = registrationRequest.Secret
	} else {
		registration, err := h.database.SelectUserTOTPRegistration(ctx, subject)
		if err != nil {
			return false, err
		}
		secret = registration.Secret
	}
	verified := h.totpProvider.VerifyCode(secret, response)
	if !verified {
		return false, nil
	}
	remoteLocation := VerifyHandlerContextValue(ctx, h)
	userVerificationLog := database.NewUserVerificationLog(subject, string(h.Method()), remoteLocation)
	_, err := h.database.InsertOrUpdateUserVerificationLog(ctx, userVerificationLog)
	return true, err
}
