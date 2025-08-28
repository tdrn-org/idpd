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
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"

	"github.com/tdrn-org/idpd/internal/server/database"
	"github.com/tdrn-org/idpd/internal/server/mail"
	"github.com/tdrn-org/idpd/internal/server/templates"
	"github.com/tdrn-org/idpd/internal/server/userstore"
)

type EmailVerifyHandler struct {
	mailer    *mail.Mailer
	database  database.Driver
	userStore userstore.Backend
	tainted   bool
}

func NewEmailVerifyHandler(mailer *mail.Mailer, database database.Driver, userStore userstore.Backend) *EmailVerifyHandler {
	return &EmailVerifyHandler{
		mailer:    mailer,
		database:  database,
		userStore: userStore,
	}
}

func (*EmailVerifyHandler) Method() VerifyMethod {
	return VerifyMethodEmail
}

func (h *EmailVerifyHandler) Taint() {
	h.tainted = true
}

func (h *EmailVerifyHandler) Tainted() bool {
	return h.tainted
}

func (h *EmailVerifyHandler) GenerateChallenge(ctx context.Context, subject string) (string, error) {
	if h.tainted {
		return taintedChallenge, nil
	}
	random, err := rand.Int(rand.Reader, big.NewInt(999999))
	if err != nil {
		return "", fmt.Errorf("failed to generate verification code (cause: %w)", err)
	}
	code := fmt.Sprintf("%06d", random.Uint64())
	user, err := h.userStore.LookupUser(subject)
	if err != nil {
		return "", err
	}
	userEmail := user.Email.Address
	if userEmail == "" {
		return "", fmt.Errorf("no email defined for user (subject: %s)", subject)
	}
	userName := user.Profile.Name
	templateData := h.templateData(ctx, code)
	err = h.mailer.NewMessage().Subject("Verify your login").BodyFromHTMLTemplate(templates.FS, templates.VerficationCodeTemplate, templateData).SendTo(userEmail, userName)
	if err != nil {
		return "", err
	}
	return h.challenge(code), nil
}

func (h *EmailVerifyHandler) templateData(ctx context.Context, code string) *templates.VerificationCodeData {
	remoteLocation := VerifyHandlerContextValue(ctx, h)
	ns := func(s string) string {
		if s != "" {
			return s
		}
		return "-"
	}
	templateData := &templates.VerificationCodeData{
		Code:        code,
		Host:        remoteLocation.Host,
		Country:     ns(remoteLocation.Country),
		CountryCode: ns(remoteLocation.CountryCode),
		City:        ns(remoteLocation.City),
		Lon:         strconv.FormatFloat(remoteLocation.Lon, 'f', 6, 64),
		Lat:         strconv.FormatFloat(remoteLocation.Lat, 'f', 6, 64),
	}
	return templateData
}

func (h *EmailVerifyHandler) VerifyResponse(ctx context.Context, subject string, challenge string, response string) (bool, error) {
	if challenge == taintedChallenge {
		h.tainted = true
		return false, nil
	}
	if challenge != h.challenge(response) {
		return false, nil
	}
	remoteLocation := VerifyHandlerContextValue(ctx, h)
	userVerificationLog := database.NewUserVerificationLog(subject, string(h.Method()), remoteLocation)
	_, err := h.database.InsertOrUpdateUserVerificationLog(ctx, userVerificationLog)
	return true, err
}

func (h *EmailVerifyHandler) challenge(code string) string {
	return string(VerifyMethodEmail) + ":" + code
}
