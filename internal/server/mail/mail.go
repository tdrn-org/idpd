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

package mail

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-tlsconf/tlsclient"
	"github.com/wneessen/go-mail"
)

type MailConfig struct {
	Address          string
	User             string
	Password         string
	FromAddress      string
	FromName         string
	OpportunisticTLS bool
}

func (c *MailConfig) NewMailer() (*Mailer, error) {
	host, portString, err := net.SplitHostPort(c.Address)
	port := 0
	if err != nil {
		host = c.Address
	} else {
		port, err = strconv.Atoi(portString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Mail server port '%s' (cause: %w)", portString, err)
		}
	}
	tlsPolicy := mail.TLSMandatory
	if c.OpportunisticTLS {
		tlsPolicy = mail.TLSOpportunistic
	}
	logger := slog.With("address", c.Address)
	mailer := &Mailer{
		host:        host,
		port:        port,
		user:        c.User,
		password:    c.Password,
		fromAddress: c.FromAddress,
		fromName:    c.FromName,
		tlsPolicy:   tlsPolicy,
		logger:      logger,
	}
	return mailer, nil
}

type Mailer struct {
	host        string
	port        int
	user        string
	password    string
	fromAddress string
	fromName    string
	tlsPolicy   mail.TLSPolicy
	logger      *slog.Logger
	client      *mail.Client
	mutex       sync.Mutex
}

func (m *Mailer) getClient(reset bool) (*mail.Client, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if !reset && m.client != nil {
		return m.client, nil
	}
	client, err := m.newClient()
	if err != nil {
		return nil, err
	}
	m.client = client
	return m.client, nil
}

func (m *Mailer) newClient() (*mail.Client, error) {
	clientTLSConfig, _ := conf.LookupConfiguration[*tlsclient.Config]()
	options := make([]mail.Option, 0, 6)
	if m.user != "" || m.password != "" {
		options = append(options, mail.WithUsername(m.user), mail.WithPassword(m.password), mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover))
	}
	tlsConfig := clientTLSConfig.Config.Clone()
	tlsConfig.ServerName = m.host
	options = append(options, mail.WithTLSConfig(tlsConfig), mail.WithTLSPolicy(m.tlsPolicy))
	if m.port != 0 {
		options = append(options, mail.WithPort(m.port))
	}
	client, err := mail.NewClient(m.host, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new Mail client (cause: %w)", err)
	}
	return client, nil
}

func (m *Mailer) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.client != nil {
		return m.client.Close()
	}
	return nil
}

func (m *Mailer) Ping() error {
	client, err := m.getClient(false)
	if err != nil {
		return err
	}
	err = client.DialWithContext(context.Background())
	if err != nil {
		return fmt.Errorf("failed to connect to Mail server (cause: %w)", err)
	}
	return nil
}

func (m *Mailer) NewMessage() *MessageBuilder {
	message := mail.NewMsg()
	builder := &MessageBuilder{
		mailer:  m,
		message: message,
		errs:    make([]error, 0),
	}
	var err error
	if m.fromName != "" {
		err = message.FromFormat(m.fromName, m.fromAddress)
	} else {
		err = message.From(m.fromAddress)
	}
	if err != nil {
		builder.errs = append(builder.errs, fmt.Errorf("failed to set FROM header (cause: %w)", err))
	}
	return builder
}

func (m *Mailer) sendMessage(message *mail.Msg) error {
	client, err := m.getClient(false)
	if err != nil {
		return err
	}
	sendErr := client.DialAndSend(message)
	if sendErr == nil {
		return nil
	}
	resetErr := client.Reset()
	if resetErr != nil {
		client, err = m.getClient(true)
	}
	if err != nil {
		return err
	}
	resendErr := client.DialAndSend(message)
	if resendErr != nil {
		return fmt.Errorf("failed to send mail (cause: %w)", errors.Join(sendErr, resendErr))
	}
	return err
}

type MessageBuilder struct {
	mailer  *Mailer
	message *mail.Msg
	errs    []error
}

func (m *MessageBuilder) Subject(subject string) *MessageBuilder {
	m.message.Subject(subject)
	return m
}

func (m *MessageBuilder) Body(contentType mail.ContentType, body string) *MessageBuilder {
	m.message.SetBodyString(contentType, body)
	return m
}

func (m *MessageBuilder) BodyFromHTMLTemplate(fs fs.FS, file string, data any) *MessageBuilder {
	tmpl, err := template.ParseFS(fs, file)
	if err != nil {
		m.errs = append(m.errs, err)
		return m
	}
	buffer := &strings.Builder{}
	err = tmpl.Execute(buffer, data)
	if err != nil {
		m.errs = append(m.errs, err)
		return m
	}
	return m.Body(mail.TypeTextHTML, buffer.String())
}

func (m *MessageBuilder) SendTo(address string, name string) error {
	err := m.message.AddToFormat(name, address)
	if err != nil {
		m.errs = append(m.errs, err)
	}
	if len(m.errs) > 0 {
		return fmt.Errorf("failed to build mail message (cause: %w)", errors.Join(m.errs...))
	}
	return m.mailer.sendMessage(m.message)
}
