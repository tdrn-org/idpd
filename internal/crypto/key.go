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
	"errors"
	"strings"

	"github.com/google/uuid"
)

var ErrInvalidKeyID error = errors.New("invalid key id")

type KeyID string

func NewKeyID(keyType string) string {
	return keyType + ":" + uuid.NewString()
}

func DecodeKeyID(keyID KeyID) (string, string, error) {
	split := strings.Split(string(keyID), ":")
	if len(split) != 2 {
		return "", "", ErrInvalidKeyID
	}
	return split[0], split[1], nil
}

type Key struct {
	ID     KeyID
	Secret []byte
}

func NewKey32(keyType string) (*Key, error) {
	secret, err := Rand32()
	if err != nil {
		return nil, err
	}
	key := &Key{
		ID:     KeyID(NewKeyID(keyType)),
		Secret: secret[:],
	}
	return key, nil
}
