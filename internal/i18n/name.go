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
	"database/sql/driver"
	"encoding/json"

	"golang.org/x/text/language"
)

type Name map[language.Tag]string

func (name Name) Equal(name2 Name) bool {
	// Do fast check for empty names
	if len(name) == 0 {
		return len(name2) == 0
	}
	defaultLocale := DefaultLocale()
	return name[defaultLocale] == name2[defaultLocale]
}

func (name Name) String() string {
	return name.Get(DefaultLocale())
}

func (name Name) Value() (driver.Value, error) {
	value, err := json.Marshal(name)
	if err != nil {
		return nil, err
	}
	return string(value), nil
}

func (name *Name) Scan(src any) error {
	return json.Unmarshal([]byte(src.(string)), name)
}

func (name Name) Set(locale language.Tag, s string) {
	name[locale] = s
}

func (name Name) Get(locale language.Tag) string {
	localizedName := name[Match(locale)]
	if localizedName == "" {
		localizedName = name[Match(DefaultLocale())]
	}
	return localizedName
}
