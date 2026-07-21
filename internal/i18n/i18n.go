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
	"context"

	"golang.org/x/text/language"
)

var SupportedLocales []language.Tag = []language.Tag{language.English, language.German}

func DefaultLocale() language.Tag {
	return SupportedLocales[0]
}

var languageMatcher language.Matcher = language.NewMatcher(SupportedLocales)

func Match(l ...language.Tag) language.Tag {
	_, index, _ := languageMatcher.Match(l...)
	return SupportedLocales[index]
}

func MatchAcceptLanguage(header []string) language.Tag {
	locale := DefaultLocale()
	if len(header) > 0 {
		l, _, _ := language.ParseAcceptLanguage(header[0])
		locale = Match(l...)
	}
	return locale
}

type contextKey string

const localeContextKey contextKey = "locale"

func WithLocale(ctx context.Context, locale language.Tag) context.Context {
	return context.WithValue(ctx, localeContextKey, locale)
}

func Locale(ctx context.Context) language.Tag {
	value := ctx.Value(localeContextKey)
	if value == nil {
		return DefaultLocale()
	}
	return value.(language.Tag)
}
