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

package database_test

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-log"
	"github.com/tdrn-org/idpd/internal/server/database"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

func TestMemoryDB(t *testing.T) {
	d, err := database.OpenMemoryDB(slog.Default())
	require.NoError(t, err)
	testDriver(t, d)
	err = d.Close()
	require.NoError(t, err)
}

func TestSQLite3DB(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "sqlite3.db")
	d, err := database.OpenSQLite3DB(file, slog.Default())
	require.NoError(t, err)
	testDriver(t, d)
	err = d.Close()
	require.NoError(t, err)
}

func TestPosgres(t *testing.T) {
	dsn := "postgres://idpd:dbpassword@localhost:5432/idpd"
	d, err := database.OpenPostgresDB(dsn, slog.Default())
	require.NoError(t, err)
	testDriver(t, d)
	err = d.Close()
	require.NoError(t, err)
}

func testDriver(t *testing.T, d database.Driver) {
	ping(t, d)
	schema1Update(t, d)
	oauth2AuthRequest(t, d)
	oauth2AuthCode(t, d)
	oauth2Token(t, d)
	oauth2RefreshToken(t, d)
	signingKey(t, d)
	userSession(t, d)
	userVerificationLog(t, d)
}

func ping(t *testing.T, d database.Driver) {
	err := d.Ping(t.Context())
	require.NoError(t, err)
}

func schema1Update(t *testing.T, d database.Driver) {
	ctx := t.Context()

	fromSchema, toSchema, err := d.UpdateSchema(ctx)
	require.NoError(t, err)
	require.Equal(t, database.SchemaNone, fromSchema)
	require.Equal(t, database.Schema1, toSchema)

	fromSchema, toSchema, err = d.UpdateSchema(ctx)
	require.NoError(t, err)
	require.Equal(t, database.Schema1, fromSchema)
	require.Equal(t, database.Schema1, toSchema)
}

func generateAndInsertOAuth2AuthRequest(t *testing.T, d database.Driver) *database.OAuth2AuthRequest {
	authRequest := &database.OAuth2AuthRequest{
		ID:       uuid.NewString(),
		ACR:      "acr",
		AMR:      []string{"amr0", "amr1"},
		Audience: []string{"audience0", "audience1"},
		Expiry:   time.Now().Add(time.Hour).UnixMicro(),
		AuthTime: time.Time{}.UnixMicro(),
		ClientID: "clientID",
		CodeChallenge: &oidc.CodeChallenge{
			Challenge: oidc.NewSHACodeChallenge("code"),
			Method:    oidc.CodeChallengeMethodS256,
		},
		Nonce:        "nonce",
		RedirectURL:  "redirectURL",
		ResponseType: oidc.ResponseTypeCode,
		ResponseMode: oidc.ResponseModeFormPost,
		Scopes:       []string{"scope0", "scope1"},
		State:        "state",
		Subject:      "",
		Done:         false,
	}
	err := d.InsertOAuth2AuthRequest(t.Context(), authRequest)
	require.NoError(t, err)
	return authRequest
}

func oauth2AuthRequest(t *testing.T, d database.Driver) {
	ctx := t.Context()
	authRequest0 := generateAndInsertOAuth2AuthRequest(t, d)

	authRequest1, err := d.SelectOAuth2AuthRequest(ctx, authRequest0.ID)
	require.NoError(t, err)
	require.Equal(t, authRequest0, authRequest1)

	generateChallenge := func(_ context.Context, _ string) (string, error) { return "challenge", nil }
	err = d.AuthenticateOAuth2AuthRequest(ctx, authRequest1.ID, "subject", generateChallenge, true)
	require.NoError(t, err)

	verifyChallengeResponse := func(_ context.Context, _ string, _ string, _ string) (bool, error) { return true, nil }
	userSessionRequest, err := d.VerifyAndTransformOAuth2AuthRequestToUserSessionRequest(ctx, authRequest1.ID, "subject", verifyChallengeResponse, "")
	require.NoError(t, err)
	require.Equal(t, authRequest1.State, userSessionRequest.State)
	require.True(t, userSessionRequest.Remember)
	authRequest2, err := d.SelectOAuth2AuthRequest(ctx, authRequest0.ID)
	require.NoError(t, err)
	authRequest1.AuthTime = authRequest2.AuthTime
	authRequest1.Subject = "subject"
	authRequest1.Challenge = "challenge"
	authRequest1.Remember = true
	authRequest1.Done = true
	require.Equal(t, authRequest1, authRequest2)

	err = d.DeleteOAuth2AuthRequest(ctx, authRequest0.ID)
	require.NoError(t, err)
	authRequest3, err := d.SelectOAuth2AuthRequest(ctx, authRequest0.ID)
	require.ErrorIs(t, err, database.ErrObjectNotFound)
	require.Nil(t, authRequest3)
}

func oauth2AuthCode(t *testing.T, d database.Driver) {
	ctx := t.Context()
	authRequest0 := generateAndInsertOAuth2AuthRequest(t, d)

	code := uuid.NewString()
	err := d.InsertOAuth2AuthCode(ctx, code, authRequest0.ID)
	require.NoError(t, err)

	authRequest1, err := d.SelectOAuth2AuthRequestByCode(ctx, code)
	require.NoError(t, err)
	require.Equal(t, authRequest0, authRequest1)

	err = d.DeleteOAuth2AuthRequest(ctx, authRequest0.ID)
	require.NoError(t, err)
}

func generateAndInsertOAuth2Token(t *testing.T, d database.Driver) *database.OAuth2Token {
	token := &database.OAuth2Token{
		ID:             uuid.NewString(),
		ClientID:       "clientID",
		Subject:        "subject",
		RefreshTokenID: "refreshTokenId",
		Audience:       []string{"audience0", "audience1"},
		Expiry:         time.Now().Add(time.Hour).UnixMicro(),
		Scopes:         []string{"scope0", "scope1"},
	}
	err := d.InsertOAuth2Token(t.Context(), token)
	require.NoError(t, err)
	return token
}

func oauth2Token(t *testing.T, d database.Driver) {
	ctx := t.Context()
	token0 := generateAndInsertOAuth2Token(t, d)

	token1, err := d.SelectOAuth2Token(ctx, token0.ID)
	require.NoError(t, err)
	require.Equal(t, token0, token1)

	err = d.DeleteOAuth2Token(ctx, token0.ID)
	require.NoError(t, err)
	_, err = d.SelectOAuth2Token(ctx, token0.ID)
	require.ErrorIs(t, err, database.ErrObjectNotFound)
}

func generateAndInsertOAuth2RefreshToken(t *testing.T, d database.Driver) *database.OAuth2RefreshToken {
	refreshTokenID := database.NewOAuth2RefreshTokenID()
	token := &database.OAuth2Token{
		ID:             uuid.NewString(),
		ClientID:       "clientID",
		Subject:        "subject",
		RefreshTokenID: refreshTokenID,
		Audience:       []string{"audience0", "audience1"},
		Expiry:         time.Now().Add(time.Hour).UnixMicro(),
		Scopes:         []string{"scope0", "scope1"},
	}
	refreshToken := &database.OAuth2RefreshToken{
		ID:            refreshTokenID,
		AuthTime:      time.Now().UnixMicro(),
		AMR:           []string{"amr0", "amr1"},
		Audience:      []string{"audience0", "audience1"},
		Subject:       "subject",
		ClientID:      "clientID",
		Expiry:        time.Now().Add(time.Hour).UnixMicro(),
		Scopes:        []string{"scope0", "scope1"},
		AccessTokenID: token.ID,
	}
	err := d.InsertOAuth2RefreshToken(t.Context(), refreshToken, token)
	require.NoError(t, err)
	return refreshToken
}

func oauth2RefreshToken(t *testing.T, d database.Driver) {
	ctx := t.Context()
	refreshToken0 := generateAndInsertOAuth2RefreshToken(t, d)

	token0, err := d.SelectOAuth2Token(ctx, refreshToken0.AccessTokenID)
	require.NoError(t, err)
	require.Equal(t, refreshToken0.ID, token0.RefreshTokenID)
	require.Equal(t, refreshToken0.ClientID, token0.ClientID)
	require.Equal(t, refreshToken0.Subject, token0.Subject)

	refreshToken1, err := d.SelectOAuth2RefreshToken(ctx, refreshToken0.ID)
	require.NoError(t, err)
	require.Equal(t, refreshToken0, refreshToken1)

	newRefreshTokenID := uuid.NewString()
	newToken := &database.OAuth2Token{
		ID:             uuid.NewString(),
		ClientID:       "clientID",
		Subject:        "subject",
		RefreshTokenID: newRefreshTokenID,
		Audience:       []string{"audience0", "audience1"},
		Expiry:         time.Now().UnixMicro(),
		Scopes:         []string{"scope0", "scope1"},
	}
	newRefreshToken0, err := d.RenewOAuth2RefreshToken(ctx, refreshToken1.ID, newToken)
	require.NoError(t, err)
	require.Equal(t, newRefreshTokenID, newRefreshToken0.ID)
	require.Equal(t, refreshToken1.AMR, newRefreshToken0.AMR)
	require.Equal(t, refreshToken1.Audience, newRefreshToken0.Audience)
	require.Equal(t, refreshToken1.Subject, newRefreshToken0.Subject)
	require.Equal(t, refreshToken1.ClientID, newRefreshToken0.ClientID)
	require.Equal(t, refreshToken1.Scopes, newRefreshToken0.Scopes)

	err = d.DeleteOAuth2TokensBySubject(ctx, refreshToken0.ClientID, refreshToken0.Subject)
	require.NoError(t, err)
	_, err = d.SelectOAuth2RefreshToken(ctx, newRefreshTokenID)
	require.ErrorIs(t, err, database.ErrObjectNotFound)
}

func signingKey(t *testing.T, d database.Driver) {
	ctx := t.Context()

	now := time.Now().UnixMicro()
	signingKeys0, err := d.RotateSigningKeys(ctx, jose.RS256, now, database.NewSigningKeyForAlgorithm)
	require.NoError(t, err)
	require.Len(t, signingKeys0, 1)
	signingKeys1, err := d.RotateSigningKeys(ctx, jose.PS256, now, database.NewSigningKeyForAlgorithm)
	require.NoError(t, err)
	require.Len(t, signingKeys1, 2)
}

func userSession(t *testing.T, d database.Driver) {
	ctx := t.Context()
	authRequest0 := generateAndInsertOAuth2AuthRequest(t, d)

	generateChallenge := func(_ context.Context, _ string) (string, error) { return "challenge", nil }
	err := d.AuthenticateOAuth2AuthRequest(ctx, authRequest0.ID, "subject", generateChallenge, true)
	require.NoError(t, err)

	verifyChallengeResponse := func(_ context.Context, _ string, _ string, _ string) (bool, error) { return true, nil }
	userSessionRequest0, err := d.VerifyAndTransformOAuth2AuthRequestToUserSessionRequest(ctx, authRequest0.ID, "subject", verifyChallengeResponse, "")
	require.NoError(t, err)

	oauth2Token := &oauth2.Token{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		Expiry:       time.Now(),
	}
	userSession0, remember, err := d.TransformAndDeleteUserSessionRequest(ctx, userSessionRequest0.State, oauth2Token)
	require.NoError(t, err)
	require.True(t, remember)
	require.Equal(t, oauth2Token.AccessToken, userSession0.AccessToken)
	require.Equal(t, oauth2Token.RefreshToken, userSession0.RefreshToken)
	require.Equal(t, oauth2Token.Expiry.UnixMicro(), userSession0.TokenExpiry)
}

func userVerificationLog(t *testing.T, d database.Driver) {
	ctx := t.Context()

	log0 := database.NewUserVerificationLog("subject", "method", "host")
	log1, err := d.InsertOrUpdateUserVerificationLog(ctx, log0)
	require.NoError(t, err)
	require.Equal(t, log0, log1)

	log1.LastUsed = time.UnixMicro(log1.LastUsed).Add(time.Second).UnixMicro()
	log2, err := d.InsertOrUpdateUserVerificationLog(ctx, log1)
	require.NoError(t, err)
	require.Equal(t, log1, log2)

	logs, err := d.SelectUserVerificationLogs(ctx, log0.Subject)
	require.NoError(t, err)
	require.Len(t, logs, 1)
	require.Equal(t, log2, logs[0])
}

func init() {
	log.Init(slog.LevelDebug, log.TargetStdout, log.ColorAuto)
}
