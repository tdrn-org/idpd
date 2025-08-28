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
	"github.com/tdrn-org/idpd/internal/server/geoip"
)

type VerifyMethod string

const (
	VerifyMethodNone     VerifyMethod = ""
	VerifyMethodEmail    VerifyMethod = VerifyMethod(database.EmailKey)
	VerifyMethodTOTP     VerifyMethod = VerifyMethod(database.TOTPKey)
	VerifyMethodPasskey  VerifyMethod = VerifyMethod(database.PasskeyKey)
	VerifyMethodWebAuthn VerifyMethod = VerifyMethod(database.WebAuthnKey)
)

const taintedChallenge string = "tainted"

type VerifyHandler interface {
	Method() VerifyMethod
	Taint()
	Tainted() bool
	GenerateChallenge(ctx context.Context, subject string) (string, error)
	VerifyResponse(ctx context.Context, subject string, challenge string, response string) (bool, error)
}

func VerifyHandlerContext(ctx context.Context, handler VerifyHandler, location *geoip.Location) context.Context {
	return context.WithValue(ctx, handler, location)
}

func VerifyHandlerContextValue(ctx context.Context, handler VerifyHandler) *geoip.Location {
	return ctx.Value(handler).(*geoip.Location)
}

func NoneVerifyHandler() VerifyHandler {
	return &noneVerifyHandler{}
}

type noneVerifyHandler struct{}

func (*noneVerifyHandler) Method() VerifyMethod {
	return VerifyMethodNone
}

func (*noneVerifyHandler) Taint() {
	// Nothing to do here
}

func (*noneVerifyHandler) Tainted() bool {
	return true
}

func (*noneVerifyHandler) GenerateChallenge(_ context.Context, _ string) (string, error) {
	return taintedChallenge, nil
}

func (h *noneVerifyHandler) VerifyResponse(_ context.Context, _ string, _ string, _ string) (bool, error) {
	return false, nil
}
