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
	"net"
	stdmail "net/mail"
	"strconv"
	"time"

	mailnotification "github.com/tdrn-org/go-notify/mail"
	"github.com/tdrn-org/idpd/config"
)

type factoryConfig struct {
	cfg *config.MailConfig
}

func (c *factoryConfig) GetServerAddress() (string, int, error) {
	host, portString, err := net.SplitHostPort(c.cfg.Address)
	if err != nil {
		return c.cfg.Address, 0, nil
	}
	port, _ := strconv.Atoi(portString)
	return host, port, nil
}

func (c *factoryConfig) GetUser() (string, error) {
	return c.cfg.User, nil
}

func (c *factoryConfig) GetPassword() (string, error) {
	return c.cfg.Password, nil
}

func (c *factoryConfig) GetFromAddress() (string, error) {
	return c.cfg.FromAddress, nil
}

func (c *factoryConfig) GetFromName() (string, error) {
	return c.cfg.FromName, nil
}

func (c *factoryConfig) GetKeepAliveTimeout() (time.Duration, error) {
	return time.Duration(c.cfg.KeepAliveTimeout), nil
}

func (c *factoryConfig) GetTLSMode() (mailnotification.TLSMode, error) {
	return mailnotification.TLSMode(c.cfg.TLSMode), nil
}

func (c *factoryConfig) GetEHLOIdentity() (string, error) {
	return c.cfg.EHLOIdentity, nil
}

func (c *factoryConfig) ResolveRecipients(ctx context.Context, params configParams) ([]*stdmail.Address, error) {
	return params.ResolveRecipients()
}

func (c *factoryConfig) ResolveSubject(ctx context.Context, params configParams) (string, error) {
	return params.ResolveSubject()
}
