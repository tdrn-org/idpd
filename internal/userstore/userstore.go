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

package userstore

import (
	"context"
	"fmt"
	"io"

	"github.com/tdrn-org/idpd/internal/domain"
)

type Type string

func (t Type) String() string {
	return string(t)
}

type Config interface {
	Type() Type
	StoreName() string
}

type Backend interface {
	Config
	Ping(ctx context.Context) error
	domain.UserStore
	io.Closer
}

type OpenFunc func(config Config) (Backend, error)

var backends map[Type]OpenFunc = make(map[Type]OpenFunc)

func RegisterBackend(backendType Type, open OpenFunc) {
	backends[backendType] = open
}

func Open(config Config) (Backend, error) {
	backendType := config.Type()
	open, ok := backends[backendType]
	if !ok {
		return nil, fmt.Errorf("unknown userstore backend type '%s'", backendType)
	}
	return open(config)
}
