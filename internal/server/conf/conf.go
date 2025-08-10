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

package conf

import (
	"crypto/rand"
	"reflect"
	"time"

	"github.com/tdrn-org/go-conf"
)

type Runtime struct {
	SessionLifetime time.Duration
	RequestLifetime time.Duration
	TokenLifetime   time.Duration
	CryptoSeed      string
}

var defaultRuntime *Runtime = &Runtime{
	SessionLifetime: 720 * time.Hour,
	RequestLifetime: 5 * time.Minute,
	TokenLifetime:   1 * time.Hour,
	CryptoSeed:      rand.Text(),
}

func (c *Runtime) Type() reflect.Type {
	return reflect.TypeFor[*Runtime]()
}

func (c *Runtime) Bind() {
	conf.BindConfiguration(c)
}

func LookupRuntime() *Runtime {
	return conf.LookupConfigurationOrDefault(defaultRuntime)
}

func BindToRuntime(apply func(conf.Configuration)) {
	conf.BindToConfiguration(defaultRuntime.Type(), apply)
}

func init() {
	defaultRuntime.Bind()
}
