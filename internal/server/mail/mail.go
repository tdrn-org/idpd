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
	gomail "gopkg.in/gomail.v2"
)

type MailConfig struct {
	Address     string
	User        string
	Password    string
	FromAddress string
	FromName    string
}

func (c *MailConfig) NewMailer() (*Mailer, error) {
	host, portString, err := net.SplitHostPort(c.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SMTP server address '%s' (cause: %w)", c.Address, err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SMTP server port '%s' (cause: %w)", portString, err)
	}
	logger := slog.With("address", c.Address)
	mailer := &Mailer{
		host:        host,
		port:        port,
		user:        c.User,
		password:    c.Password,
		fromAddress: c.FromAddress,
		fromName:    c.FromName,
		logger:      logger,
	}
	mailer.dialerPool.New = mailer.newDialer
	return mailer, nil
}

type Mailer struct {
	host        string
	port        int
	user        string
	password    string
	fromAddress string
	fromName    string
	dialerPool  sync.Pool
	logger      *slog.Logger
}

func (m *Mailer) Ping() error {
	dialer := m.getDialer()
	defer m.releaseDialer(dialer)
	closer, err := dialer.Dial()
	if err != nil {
		return fmt.Errorf("failed to connect to mail server (cause: %w)", err)
	}
	closer.Close()
	return nil
}

func (m *Mailer) NewMessage() *MessageBuilder {
	message := gomail.NewMessage()
	message.SetAddressHeader("From", m.fromAddress, m.fromName)
	return &MessageBuilder{
		mailer:  m,
		message: message,
		errs:    make([]error, 0),
	}
}

func (m *Mailer) sendMessage(message *gomail.Message) error {
	dialer := m.getDialer()
	defer m.releaseDialer(dialer)
	err := dialer.DialAndSend(message)
	if err != nil {
		return fmt.Errorf("failed to send mail (cause: %w)", err)
	}
	return err
}

func (m *Mailer) newDialer() any {
	dialer := gomail.NewDialer(m.host, m.port, m.user, m.password)
	clientTLSConfig, _ := conf.LookupConfiguration[*tlsclient.Config]()
	dialer.TLSConfig = clientTLSConfig.Config.Clone()
	dialer.TLSConfig.ServerName = m.host
	return dialer
}

func (m *Mailer) getDialer() *gomail.Dialer {
	return m.dialerPool.Get().(*gomail.Dialer)
}

func (m *Mailer) releaseDialer(dialer *gomail.Dialer) {
	m.dialerPool.Put(dialer)
}

type MessageBuilder struct {
	mailer  *Mailer
	message *gomail.Message
	errs    []error
}

func (m *MessageBuilder) Subject(subject string) *MessageBuilder {
	m.message.SetHeader("Subject", subject)
	return m
}

func (m *MessageBuilder) Body(contentType string, body string) *MessageBuilder {
	m.message.SetBody(contentType, body)
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
	return m.Body("text/html", buffer.String())
}

func (m *MessageBuilder) SendTo(address string, name string) error {
	if len(m.errs) > 0 {
		return fmt.Errorf("failed to build mail message (cause: %w)", errors.Join(m.errs...))
	}
	m.message.SetAddressHeader("To", address, name)
	return m.mailer.sendMessage(m.message)
}
