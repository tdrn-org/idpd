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

package mail_test

import (
	"embed"
	"fmt"
	"testing"

	smtpmock "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/server/mail"
)

//go:embed testdata/*.tmpl
var testTemplates embed.FS

type testData struct {
	Title   string
	Message string
}

func TestMailer(t *testing.T) {
	smtpMock := smtpmock.New(smtpmock.ConfigurationAttr{
		LogToStdout:       true,
		LogServerActivity: true,
	})
	err := smtpMock.Start()
	require.NoError(t, err)
	defer smtpMock.Stop()

	config := &mail.MailConfig{
		Address:     fmt.Sprintf("localhost:%d", smtpMock.PortNumber()),
		User:        "smtpuser",
		Password:    "smtppassword",
		FromAddress: "test@example.org",
		FromName:    "Test",
	}
	mailer, err := config.NewMailer()
	require.NoError(t, err)
	err = mailer.Ping()
	require.NoError(t, err)

	data := &testData{
		Title:   "title",
		Message: "message",
	}
	err = mailer.NewMessage().Subject("Test email").BodyFromHTMLTemplate(testTemplates, "testdata/test.tmpl", data).SendTo("test@example.org", "Test")
	require.NoError(t, err)
}
