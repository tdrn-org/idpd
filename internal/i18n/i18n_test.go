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
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/i18n"
	"golang.org/x/text/language"
)

func TestDefaultLocale(t *testing.T) {
	locale := i18n.DefaultLocale()
	require.Equal(t, language.English, locale)
}

func TestMatch(t *testing.T) {
	// Match exact locales
	testLocales := []language.Tag{language.English, language.German}
	for _, testLocale := range testLocales {
		locale := i18n.Match(testLocale)
		require.Equal(t, testLocale, locale)
	}

	// Match over-specific locales
	testLocales = []language.Tag{language.AmericanEnglish, language.BritishEnglish}
	for _, testLocale := range testLocales {
		locale := i18n.Match(testLocale)
		require.Equal(t, language.English, locale)
	}

	// Match unsupported locales
	testLocales = []language.Tag{language.CanadianFrench, language.French}
	for _, testLocale := range testLocales {
		locale := i18n.Match(testLocale)
		require.Equal(t, language.English, locale)
	}

	// Match no locales
	locale := i18n.Match()
	require.Equal(t, language.English, locale)
}

func TestMatchAcceptLanguage(t *testing.T) {
	// Empty header
	locale := i18n.MatchAcceptLanguage(nil)
	require.Equal(t, language.English, locale)
	locale = i18n.MatchAcceptLanguage([]string{})
	require.Equal(t, language.English, locale)

	// English header
	locale = i18n.MatchAcceptLanguage([]string{"en-US,en"})
	require.Equal(t, language.English, locale)

	// German header
	locale = i18n.MatchAcceptLanguage([]string{"de-DE,de"})
	require.Equal(t, language.German, locale)

	// French header
	locale = i18n.MatchAcceptLanguage([]string{"fr-FR,fr"})
	require.Equal(t, language.English, locale)
}

func TestWithLocale(t *testing.T) {
	// Default locale, if no locale is set
	locale := i18n.Locale(context.TODO())
	require.Equal(t, language.English, locale)

	// Set locale, if one is set
	i18nCtx := i18n.WithLocale(context.TODO(), language.German)
	locale = i18n.Locale(i18nCtx)
	require.Equal(t, language.German, locale)
}
