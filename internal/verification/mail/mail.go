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

package mail

import (
	"context"
	"fmt"
	stdmail "net/mail"

	mailnotification "github.com/tdrn-org/go-notify/mail"
	"github.com/tdrn-org/idpd/config"
	"github.com/tdrn-org/idpd/internal/crypto"
	"github.com/tdrn-org/idpd/internal/domain"
	"github.com/tdrn-org/idpd/internal/verification"
)

const codeLenght int = 6

type Handler struct {
	runtime        verification.Runtime
	messageFactory *mailnotification.PayloadFactory[configParams]
}

func NewHandler(runtime verification.Runtime, cfg *config.MailConfig) (*Handler, error) {
	messageFactory, err := mailnotification.NewPayloadFactory(&factoryConfig{cfg: cfg})
	if err != nil {
		return nil, err
	}
	handler := &Handler{
		runtime:        runtime,
		messageFactory: messageFactory,
	}
	return handler, nil
}

func (h *Handler) GenerateChallenge(ctx context.Context, user *domain.User) ([]byte, error) {
	code, err := crypto.GenerateSecureOTP(codeLenght)
	if err != nil {
		return nil, err
	}
	body, params, err := h.prepareMessage(ctx, user, code)
	if err != nil {
		return nil, err
	}
	payload := h.messageFactory.NewHTMLPayload(body)
	err = payload.Send(ctx, params)
	if err != nil {
		return nil, err
	}
	return []byte(code), nil
}

func (h *Handler) VerifyResponse(_ context.Context, challenge, response []byte) error {
	if string(challenge) != string(response) {
		return domain.ErrChallengeResponseMismatch
	}
	return nil
}

func (h *Handler) prepareMessage(ctx context.Context, user *domain.User, code string) (string, *templateParams, error) {
	body, err := loadBodyTemplate(ctx)
	if err != nil {
		return "", nil, err
	}
	if len(user.EmailAddresses) == 0 {
		return "", nil, fmt.Errorf("no email addresses defined for login '%s'", user.Login)
	}
	recipient, err := stdmail.ParseAddress(user.EmailAddresses[0])
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse email address '%s' for login '%s' (cause: %w)", user.EmailAddresses[0], user.Login, err)
	}
	params := &templateParams{
		Recipients: []*stdmail.Address{recipient},
		Code:       code,
	}
	subject, err := loadAndExecuteSubjectTemplate(ctx, params)
	if err != nil {
		return "", nil, err
	}
	params.Subject = subject
	return body, params, nil
}
