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

package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// GenerateSecureRand32 generates a new random 32-byte array for cryptographic operations.
func GenerateSecureRand32() ([32]byte, error) {
	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return key, fmt.Errorf("failed to generate random bytes (cause: %w)", err)
	}
	return key, nil
}

// GenerateSecureOTP generates a new secure one-time-password (OTP) of the given length.
func GenerateSecureOTP(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid length: %d", length)
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	random, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate code (cause: %w)", err)
	}
	return fmt.Sprintf("%0*d", length, random.Uint64()), nil
}
