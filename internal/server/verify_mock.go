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
)

func MockVerifyHandler() VerifyHandler {
	return &mockVerifyHandler{}
}

type mockVerifyHandler struct{}

func (*mockVerifyHandler) Method() VerifyMethod {
	return VerifyMethodNone
}

func (*mockVerifyHandler) Taint() {
	// Nothing to do here
}

func (*mockVerifyHandler) Tainted() bool {
	return false
}

func (*mockVerifyHandler) GenerateChallenge(_ context.Context, _ string) (string, error) {
	return string(VerifyMethodNone), nil
}

func (h *mockVerifyHandler) VerifyResponse(_ context.Context, _ string, _ string, _ string) error {
	return nil
}
