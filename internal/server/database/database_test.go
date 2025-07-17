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
	"crypto/rand"
	"crypto/rsa"
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

func TestPG(t *testing.T) {
	dsn := "postgres://idpd:dbpassword@localhost:5432/idpd"
	d, err := database.OpenPostgresDB(dsn, slog.Default())
	require.NoError(t, err)
	testDriver(t, d)
	err = d.Close()
	require.NoError(t, err)
}

func testDriver(t *testing.T, d database.Driver) {
	schema1Update(t, d)
	authRequest(t, d)
	authCode(t, d)
	token(t, d)
	refreshToken(t, d)
	signingKey(t, d)
	userSession(t, d)
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

func generateAndInsertAuthRequest(t *testing.T, d database.Driver) *database.AuthRequest {
	authRequest := &database.AuthRequest{
		ID:         uuid.NewString(),
		ACR:        "acr",
		AMR:        []string{"amr0", "amr1"},
		Audience:   []string{"audience0", "audience1"},
		CreateTime: time.Now().UnixMicro(),
		AuthTime:   time.Time{}.UnixMicro(),
		ClientID:   "clientId",
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
	err := d.InsertAuthRequest(t.Context(), authRequest)
	require.NoError(t, err)
	return authRequest
}

func authRequest(t *testing.T, d database.Driver) {
	ctx := t.Context()
	authRequest0 := generateAndInsertAuthRequest(t, d)

	authRequest1, err := d.SelectAuthRequest(ctx, authRequest0.ID)
	require.NoError(t, err)
	require.Equal(t, authRequest0, authRequest1)

	userSessionRequest, err := d.AuthenticateAndTransformAuthRequestToUserSessionRequest(ctx, authRequest1.ID, "subject", true)
	require.NoError(t, err)
	require.Equal(t, authRequest1.State, userSessionRequest.State)
	require.True(t, userSessionRequest.Remember)
	authRequest2, err := d.SelectAuthRequest(ctx, authRequest0.ID)
	require.NoError(t, err)
	authRequest1.AuthTime = authRequest2.AuthTime
	authRequest1.Subject = "subject"
	authRequest1.Done = true
	require.Equal(t, authRequest1, authRequest2)

	err = d.DeleteAuthRequest(ctx, authRequest0.ID)
	require.NoError(t, err)
	authRequest3, err := d.SelectAuthRequest(ctx, authRequest0.ID)
	require.ErrorIs(t, err, database.ErrObjectNotFound)
	require.Nil(t, authRequest3)
}

func authCode(t *testing.T, d database.Driver) {
	ctx := t.Context()
	authRequest0 := generateAndInsertAuthRequest(t, d)

	code := uuid.NewString()
	err := d.InsertAuthCode(ctx, code, authRequest0.ID)
	require.NoError(t, err)

	authRequest1, err := d.SelectAuthRequestByCode(ctx, code)
	require.NoError(t, err)
	require.Equal(t, authRequest0, authRequest1)

	err = d.DeleteAuthRequest(ctx, authRequest0.ID)
	require.NoError(t, err)
}

func generateAndInsertToken(t *testing.T, d database.Driver) *database.Token {
	token := &database.Token{
		ID:             uuid.NewString(),
		ApplicationID:  "applicationId",
		Subject:        "subject",
		RefreshTokenID: "refreshTokenId",
		Audience:       []string{"audience0", "audience1"},
		Expiration:     time.Now().UnixMicro(),
		Scopes:         []string{"scope0", "scope1"},
	}
	err := d.InsertToken(t.Context(), token)
	require.NoError(t, err)
	return token
}

func token(t *testing.T, d database.Driver) {
	ctx := t.Context()
	token0 := generateAndInsertToken(t, d)

	token1, err := d.SelectToken(ctx, token0.ID)
	require.NoError(t, err)
	require.Equal(t, token0, token1)
}

func generateAndInsertRefreshToken(t *testing.T, d database.Driver) *database.RefreshToken {
	refreshTokenID := uuid.NewString()
	token := &database.Token{
		ID:             uuid.NewString(),
		ApplicationID:  "applicationId",
		Subject:        "subject",
		RefreshTokenID: refreshTokenID,
		Audience:       []string{"audience0", "audience1"},
		Expiration:     time.Now().UnixMicro(),
		Scopes:         []string{"scope0", "scope1"},
	}
	refreshToken := &database.RefreshToken{
		ID:            refreshTokenID,
		AuthTime:      time.Now().UnixMicro(),
		AMR:           []string{"amr0", "amr1"},
		Audience:      []string{"audience0", "audience1"},
		UserID:        "userId",
		ApplicationID: "applicationId",
		Expiration:    time.Now().UnixMicro(),
		Scopes:        []string{"scope0", "scope1"},
		AccessTokenID: token.ID,
	}
	err := d.InsertRefreshToken(t.Context(), refreshToken, token)
	require.NoError(t, err)
	return refreshToken
}

func refreshToken(t *testing.T, d database.Driver) {
	ctx := t.Context()
	refreshToken0 := generateAndInsertRefreshToken(t, d)

	refreshToken1, err := d.SelectRefreshToken(ctx, refreshToken0.ID)
	require.NoError(t, err)
	require.Equal(t, refreshToken0, refreshToken1)

	newRefreshTokenID := uuid.NewString()
	newToken := &database.Token{
		ID:             uuid.NewString(),
		ApplicationID:  "applicationId",
		Subject:        "subject",
		RefreshTokenID: newRefreshTokenID,
		Audience:       []string{"audience0", "audience1"},
		Expiration:     time.Now().UnixMicro(),
		Scopes:         []string{"scope0", "scope1"},
	}
	newRefreshToken0, err := d.RenewRefreshToken(ctx, refreshToken1.ID, newToken)
	require.NoError(t, err)
	require.Equal(t, refreshToken1.AMR, newRefreshToken0.AMR)
	require.Equal(t, refreshToken1.Audience, newRefreshToken0.Audience)
	require.Equal(t, refreshToken1.UserID, newRefreshToken0.UserID)
	require.Equal(t, refreshToken1.ApplicationID, newRefreshToken0.ApplicationID)
	require.Equal(t, refreshToken1.Scopes, newRefreshToken0.Scopes)
}

func signingKey(t *testing.T, d database.Driver) {
	generateSigningKey := func(algorithm string) (*database.SigningKey, error) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		publicKey := &privateKey.PublicKey
		now := time.Now()
		passivation := now.Add(time.Second).UnixMicro()
		expiration := now.Add(10 * time.Second).UnixMicro()
		return database.NewSigningKey(algorithm, privateKey, publicKey, passivation, expiration)
	}
	ctx := t.Context()
	signingKeys0, err := d.RotateSigningKeys(ctx, string(jose.RS256), generateSigningKey)
	require.NoError(t, err)
	require.Len(t, signingKeys0, 1)
	signingKeys1, err := d.RotateSigningKeys(ctx, string(jose.PS256), generateSigningKey)
	require.NoError(t, err)
	require.Len(t, signingKeys1, 2)
}

func userSession(t *testing.T, d database.Driver) {
	ctx := t.Context()
	authRequest0 := generateAndInsertAuthRequest(t, d)

	userSessionRequest0, err := d.AuthenticateAndTransformAuthRequestToUserSessionRequest(ctx, authRequest0.ID, "subject", true)
	require.NoError(t, err)

	oauth2Token := &oauth2.Token{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		Expiry:       time.Now(),
	}
	userSession0, err := d.TransformAndDeleteUserSessionRequest(ctx, userSessionRequest0.State, oauth2Token)
	require.NoError(t, err)
	require.True(t, userSession0.Remember)
	require.Equal(t, oauth2Token.AccessToken, userSession0.AccessToken)
	require.Equal(t, oauth2Token.RefreshToken, userSession0.RefreshToken)
	require.Equal(t, oauth2Token.Expiry.UnixMicro(), userSession0.Expiration)
}

func init() {
	log.Init(slog.LevelDebug, log.TargetStdout, log.ColorAuto)
}
