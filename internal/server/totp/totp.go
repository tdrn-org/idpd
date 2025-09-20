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

package totp

import (
	"encoding/base64"
	"fmt"
	"image/png"
	"log/slog"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

type Config struct {
	Issuer string
	Period time.Duration
}

func (c *Config) NewProvider() *Provider {
	logger := slog.With(slog.String("issuer", c.Issuer))
	logger.Info("initializing TOTP provider")
	return &Provider{
		issuer: c.Issuer,
		period: c.Period,
		logger: logger,
	}
}

type Provider struct {
	issuer string
	period time.Duration
	logger *slog.Logger
}

func (p *Provider) GenerateRegistrationRequest(subject string, width int, height int) (string, string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      p.issuer,
		AccountName: subject,
		Period:      uint(p.period.Seconds()),
	})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate TOTP key (cause: %w)", err)
	}
	qrCodeImage, err := key.Image(width, height)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate TOTP QR code image (cause: %w)", err)
	}
	qrCode := &strings.Builder{}
	err = png.Encode(base64.NewEncoder(base64.StdEncoding, qrCode), qrCodeImage)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to encode TOTP QR code image (cause: %w)", err)
	}
	return key.Secret(), qrCode.String(), key.URL(), nil
}

func (p *Provider) VerifyCode(secret string, code string) bool {
	return totp.Validate(code, secret)
}
