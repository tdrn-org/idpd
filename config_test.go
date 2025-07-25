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

package idpd_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd"
)

func TestLoadConfig(t *testing.T) {
	config, err := idpd.LoadConfig("testdata/config_test.toml", true)
	require.NoError(t, err)
	require.NotNil(t, config)
}
