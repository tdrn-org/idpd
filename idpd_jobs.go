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

package idpd

import (
	"context"
	"log/slog"
)

func (s *Server) runJobs() {
	slog.Debug("running jobs")
	s.runDeleteExpiredJob()
}

func (s *Server) runDeleteExpiredJob() {
	ctx := context.Background()

	// Garbage collect OAuth2 authentication and user session requests
	err := s.database.DeleteExpiredOAuth2AuthRequests(ctx)
	if err != nil {
		slog.Error("failed to delete expired OAuth2 auth requests", slog.Any("err", err))
	}
	err = s.database.DeleteExpiredUserSessionRequests(ctx)
	if err != nil {
		slog.Error("failed to delete expired user session requests", slog.Any("err", err))
	}

	// Garbage collect OAuth2 tokens (refresh & access)

	// Garbage collect refresh tokens before access tokens, as the latter
	// may be referenced by them (and we cannot garbage collect an access
	// token still referenced by a refresh token)
	err = s.database.DeleteExpiredOAuth2RefreshTokens(ctx)
	if err != nil {
		slog.Error("failed to delete expired OAuth2 refresh tokens", slog.Any("err", err))
	}
	err = s.database.DeleteExpiredOAuth2Tokens(ctx)
	if err != nil {
		slog.Error("failed to delete expired OAuth2 tokens", slog.Any("err", err))
	}

	// Garbage collect 2FA registration requests (TOTP)
	err = s.database.DeleteExpiredUserTOTPRegistrationRequests(ctx)
	if err != nil {
		slog.Error("failed to delete expired user TOTP registration requests", slog.Any("err", err))
	}
}
