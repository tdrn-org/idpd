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

package i18n

import (
	"strings"

	"golang.org/x/text/language"
)

func FileName(name string, locale language.Tag) string {
	localeBase, _ := locale.Base()
	split := strings.LastIndex(name, ".")
	if split <= 0 {
		return name + "_" + localeBase.String()
	}
	return name[:split] + "_" + localeBase.String() + name[split:]
}
