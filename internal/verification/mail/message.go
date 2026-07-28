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

package mail

import (
	"context"
	"embed"
	"fmt"
	stdmail "net/mail"
	"strings"
	texttemplate "text/template"

	"github.com/tdrn-org/idpd/internal/i18n"
)

//go:embed *.tmpl
var templateFS embed.FS

type configParams interface {
	ResolveRecipients() ([]*stdmail.Address, error)
	ResolveSubject() (string, error)
}

type templateParams struct {
	Recipients  []*stdmail.Address
	Subject     string
	Icon        string
	Code        string
	Host        string
	Address     string
	AddressURL  string
	City        string
	Country     string
	Lat         string
	Lng         string
	LocationURL string
}

func (p *templateParams) ResolveRecipients() ([]*stdmail.Address, error) {
	return p.Recipients, nil
}

func (p *templateParams) ResolveSubject() (string, error) {
	return p.Subject, nil
}

const templateSubject string = "message_subject.tmpl"
const templateBody string = "message_body.tmpl"

func loadAndExecuteSubjectTemplate(ctx context.Context, params *templateParams) (string, error) {
	localizedName := i18n.FileName(templateSubject, i18n.Locale(ctx))
	tmpl, err := texttemplate.ParseFS(templateFS, localizedName)
	if err != nil {
		return "", fmt.Errorf("failed to load subject template '%s' (cause: %w)", localizedName, err)
	}
	buffer := &strings.Builder{}
	err = tmpl.Execute(buffer, params)
	if err != nil {
		return "", fmt.Errorf("failed to execute subject template '%s' (cause: %w)", localizedName, err)
	}
	return buffer.String(), nil
}

func loadBodyTemplate(ctx context.Context) (string, error) {
	localizedName := i18n.FileName(templateBody, i18n.Locale(ctx))
	template, err := templateFS.ReadFile(localizedName)
	if err != nil {
		return "", fmt.Errorf("failed to load body template '%s' (cause: %w)", localizedName, err)
	}
	return string(template), nil
}
