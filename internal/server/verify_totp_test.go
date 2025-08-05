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

package server_test

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestTOTPProvider(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "issuer",
		AccountName: "subject",
	})
	require.NoError(t, err)
	passcode, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)
	valid := totp.Validate(passcode, key.Secret())
	require.True(t, valid)
}
