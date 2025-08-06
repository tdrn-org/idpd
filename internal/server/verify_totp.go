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
	"encoding/base64"
	"fmt"
	"image/png"
	"log/slog"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/tdrn-org/idpd/internal/server/database"
)

type TOTPConfig struct {
	Issuer string
	Period time.Duration
}

func (c *TOTPConfig) NewTOTPProvider() *TOTPProvider {
	logger := slog.With(slog.String("issuer", c.Issuer))
	logger.Info("initializing TOTP provider")
	return &TOTPProvider{
		issuer: c.Issuer,
		period: c.Period,
		logger: logger,
	}
}

type TOTPProvider struct {
	issuer string
	period time.Duration
	logger *slog.Logger
}

func (p *TOTPProvider) GenerateRegistrationRequest(subject string, width int, height int) (string, string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      p.issuer,
		AccountName: subject,
		Period:      uint(p.period.Seconds()),
	})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate TOTP key (cause: %w)", err)
	}
	qrCodeImage, err := key.Image(width, height)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate TOTP QR code image (cause: %w)", err)
	}
	qrCode := &strings.Builder{}
	err = png.Encode(base64.NewEncoder(base64.StdEncoding, qrCode), qrCodeImage)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to encode TOTP QR code image (cause: %w)", err)
	}
	return key.Secret(), qrCode.String(), key.URL(), nil
}

func (p *TOTPProvider) VerifyCode(secret string, code string) bool {
	return totp.Validate(code, secret)
}

type TOTPVerifyHandler struct {
	totpProvider        *TOTPProvider
	database            database.Driver
	requestVerification bool
	tainted             bool
}

func NewTOTPVerifyHandler(totpProvider *TOTPProvider, database database.Driver, requestVerification bool) *TOTPVerifyHandler {
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
		secret = ""
	}
	verified := h.totpProvider.VerifyCode(secret, response)
	if !verified {
		return false, nil
	}
	userVerificationLog := ctx.Value(h).(*database.UserVerificationLog)
	_, err := h.database.InsertOrUpdateUserVerificationLog(ctx, userVerificationLog)
	return true, err
}
