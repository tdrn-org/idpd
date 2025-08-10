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
	"time"

	"github.com/tdrn-org/idpd/internal/server/database"
	"github.com/tdrn-org/idpd/internal/trace"
)

const serverJobTickerSchedule time.Duration = 5 * time.Minute

func (s *Server) runJobs() {
	traceCtx, span := s.tracer.Start(context.Background(), "runJobs")
	defer span.End()

	// Run refresh jobs first, to avoid race conditions
	s.runRefreshSessionsJob(traceCtx)
	s.runDeleteExpiredJob(traceCtx)
}

func (s *Server) runRefreshSessionsJob(ctx context.Context) {
	traceCtx, span := s.tracer.Start(ctx, "runDeleteExpiredJob")
	defer span.End()

	expiry := time.Now().Add(2 * serverJobTickerSchedule).UnixMicro()
	err := s.database.RefreshUserSessions(traceCtx, expiry, s.refreshUserSession)
	if err != nil {
		slog.Error("failed to refresh user sessions", slog.Any("err", err))
	}
}

func (s *Server) refreshUserSession(ctx context.Context, session *database.UserSession) error {
	traceCtx, span := s.tracer.Start(ctx, "refreshUserSession")
	defer span.End()

	tokenSource, err := s.authFLow.TokenSource(traceCtx, session.OAuth2Token())
	if err != nil {
		return trace.RecordError(span, err)
	}
	token, err := tokenSource.Token()
	if err != nil {
		return trace.RecordError(span, err)
	}
	refreshed := session.Refresh(token)
	if refreshed {
		err = s.database.RefreshUserSession(traceCtx, session)
		if err != nil {
			return trace.RecordError(span, err)
		}
	}
	return nil
}

func (s *Server) runDeleteExpiredJob(ctx context.Context) {
	traceCtx, span := s.tracer.Start(ctx, "runDeleteExpiredJob")
	defer span.End()

	// Garbage collect OAuth2 authentication and user session requests
	err := s.database.DeleteExpiredOAuth2AuthRequests(traceCtx)
	if err != nil {
		slog.Error("failed to delete expired OAuth2 auth requests", slog.Any("err", err))
	}
	err = s.database.DeleteExpiredUserSessionRequests(traceCtx)
	if err != nil {
		slog.Error("failed to delete expired user session requests", slog.Any("err", err))
	}

	// Garbage collect user sessions
	err = s.database.DeleteExpiredUserSessions(traceCtx)
	if err != nil {
		slog.Error("failed to delete expired user sessions", slog.Any("err", err))
	}

	// Garbage collect OAuth2 tokens (refresh & access)

	// Garbage collect refresh tokens before access tokens, as the latter
	// may be referenced by them (and we cannot garbage collect an access
	// token still referenced by a refresh token)
	err = s.database.DeleteExpiredOAuth2RefreshTokens(traceCtx)
	if err != nil {
		slog.Error("failed to delete expired OAuth2 refresh tokens", slog.Any("err", err))
	}
	err = s.database.DeleteExpiredOAuth2Tokens(traceCtx)
	if err != nil {
		slog.Error("failed to delete expired OAuth2 tokens", slog.Any("err", err))
	}

	// Garbage collect 2FA registration requests (TOTP)
	err = s.database.DeleteExpiredUserTOTPRegistrationRequests(traceCtx)
	if err != nil {
		slog.Error("failed to delete expired user TOTP registration requests", slog.Any("err", err))
	}
}
