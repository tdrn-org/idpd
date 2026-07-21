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

package i18n_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/i18n"
	"golang.org/x/text/language"
)

func TestName(t *testing.T) {
	name := make(i18n.Name)
	name.Set(language.English, "EN")
	name.Set(language.German, "DE")

	localizedName := name.Get(language.English)
	require.Equal(t, "EN", localizedName)

	localizedName = name.Get(language.German)
	require.Equal(t, "DE", localizedName)

	localizedName = name.Get(language.Norwegian)
	require.Equal(t, "EN", localizedName)

	marshaledName, err := name.Value()
	require.NoError(t, err)
	unmarshaledName := make(i18n.Name)
	err = unmarshaledName.Scan(marshaledName)
	require.NoError(t, err)
	require.Equal(t, name, unmarshaledName)
}

func TestNameEqual(t *testing.T) {
	name1 := make(i18n.Name)
	name2 := make(i18n.Name)

	// Empty equal
	require.True(t, name1.Equal(name2))

	// not equal
	name1.Set(language.English, "name")
	require.False(t, name1.Equal(name2))

	// not equal
	name2.Set(language.German, "name")
	require.False(t, name1.Equal(name2))

	// Non-empty equal
	name2.Set(language.English, "name")
	require.True(t, name1.Equal(name2))
}
