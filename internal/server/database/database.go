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

package database

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

const RequestLifetime time.Duration = 5 * time.Minute
const TokenLifetime time.Duration = 60 * time.Minute

const EmailKey string = "email"
const TOTPKey string = "totp"
const PasskeyKey string = "passkey"
const WebAuthnKey string = "webauthn"

type GenerateChallengeFunc func(ctx context.Context, subject string) (string, error)
type VerifyChallengeResponseFunc func(ctx context.Context, subject string, challenge string, response string) (bool, error)
type GenerateSigningKeyFunc func(algorithm string) (*SigningKey, error)

type Driver interface {
	Name() string
	UpdateSchema(ctx context.Context) (SchemaVersion, SchemaVersion, error)
	InsertOAuth2AuthRequest(ctx context.Context, authRequest *OAuth2AuthRequest) error
	SelectOAuth2AuthRequest(ctx context.Context, id string) (*OAuth2AuthRequest, error)
	SelectOAuth2AuthRequestByCode(ctx context.Context, code string) (*OAuth2AuthRequest, error)
	AuthenticateOAuth2AuthRequest(ctx context.Context, id string, subject string, generateChallengeFunc GenerateChallengeFunc, remember bool) error
	VerifyAndTransformOAuth2AuthRequestToUserSessionRequest(ctx context.Context, id string, subject string, verifyChallengeResponse VerifyChallengeResponseFunc, response string) (*UserSessionRequest, error)
	DeleteOAuth2AuthRequest(ctx context.Context, id string) error
	DeleteExpiredOAuth2AuthRequests(ctx context.Context) error
	InsertOAuth2AuthCode(ctx context.Context, code string, id string) error
	InsertOAuth2Token(ctx context.Context, token *OAuth2Token) error
	SelectOAuth2Token(ctx context.Context, id string) (*OAuth2Token, error)
	DeleteOAuth2Token(ctx context.Context, id string) error
	DeleteExpiredOAuth2Tokens(ctx context.Context) error
	InsertOAuth2RefreshToken(ctx context.Context, refreshToken *OAuth2RefreshToken, token *OAuth2Token) error
	RenewOAuth2RefreshToken(ctx context.Context, id string, newToken *OAuth2Token) (*OAuth2RefreshToken, error)
	SelectOAuth2RefreshToken(ctx context.Context, id string) (*OAuth2RefreshToken, error)
	DeleteOAuth2TokensBySubject(ctx context.Context, applicationID string, subject string) error
	DeleteOAuth2RefreshToken(ctx context.Context, id string) error
	DeleteExpiredOAuth2RefreshTokens(ctx context.Context) error
	RotateSigningKeys(ctx context.Context, algorithm string, generateSigningKey GenerateSigningKeyFunc) (SigningKeys, error)
	TransformAndDeleteUserSessionRequest(ctx context.Context, state string, token *oauth2.Token) (*UserSession, error)
	DeleteExpiredUserSessionRequests(ctx context.Context) error
	SelectUserSession(ctx context.Context, id string) (*UserSession, error)
	InsertOrUpdateUserVerificationLog(ctx context.Context, log *UserVerificationLog) (*UserVerificationLog, error)
	SelectUserVerificationLogs(ctx context.Context, subject string) ([]*UserVerificationLog, error)
	GenerateUserTOTPRegistrationRequest(ctx context.Context, subject string, secret string, generateChallengeFunc GenerateChallengeFunc) (*UserTOTPRegistrationRequest, error)
	SelectUserTOTPRegistrationRequest(ctx context.Context, subject string) (*UserTOTPRegistrationRequest, error)
	DeleteExpiredUserTOTPRegistrationRequests(ctx context.Context) error
	VerifyAndTransformUserTOTPRegistrationRequestToRegistration(ctx context.Context, subject string, verifyChallengeResponse VerifyChallengeResponseFunc, response string) (*UserTOTPRegistration, error)
	SelectUserTOTPRegistration(ctx context.Context, subject string) (*UserTOTPRegistration, error)
	Close() error
}

type SchemaVersion string

const (
	SchemaNone SchemaVersion = ""
	Schema1    SchemaVersion = "1"
)

func openDatabase(name string, driverName string, dsn string, logger *slog.Logger, scripts ...[]byte) (Driver, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s database (cause: %w)", name, err)
	}
	d := &databaseDriver{
		name:    name,
		db:      db,
		stmts:   make(map[string]*sql.Stmt),
		logger:  logger,
		scripts: scripts,
	}
	return d, nil
}

var ErrObjectNotFound = errors.New("object not found")

type databaseDriver struct {
	name    string
	db      *sql.DB
	stmts   map[string]*sql.Stmt
	logger  *slog.Logger
	scripts [][]byte
	mutex   sync.RWMutex
}

func (d *databaseDriver) Name() string {
	return d.name
}

func (d *databaseDriver) UpdateSchema(ctx context.Context) (SchemaVersion, SchemaVersion, error) {
	// Run schema version query inside separate TX, as some drivers will fail due the
	// errors encountered while detecting the version on an empty database.
	fromVersion, err := d.querySchemaVersion(ctx)
	if err != nil {
		return SchemaNone, SchemaNone, err
	}
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return SchemaNone, SchemaNone, err
	}
	switch fromVersion {
	case SchemaNone:
		d.logger.Debug("running schema1 update script")
		err = d.runScriptTx(tx, txCtx, d.scripts[0])
	case Schema1:
		// Nothing to do
		d.logger.Debug("schema already up-to-date; no update required")
	default:
		err = fmt.Errorf("unrecognized database schema version: %s", fromVersion)
	}
	if err != nil {
		return SchemaNone, SchemaNone, d.rollbackTx(tx, err)
	}
	return fromVersion, Schema1, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) querySchemaVersion(ctx context.Context) (SchemaVersion, error) {
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return SchemaNone, err
	}
	row, err := d.queryRowTx(tx, txCtx, "SELECT schema FROM version")
	if err != nil {
		return SchemaNone, d.rollbackTx(tx, nil)
	}
	var schema SchemaVersion
	err = row.Scan(&schema)
	if err != nil {
		return SchemaNone, d.rollbackTx(tx, nil)
	}
	return schema, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) InsertOAuth2AuthRequest(ctx context.Context, authRequest *OAuth2AuthRequest) error {
	d.logger.Debug("inserting OAuth2 auth request", slog.String("id", authRequest.ID))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	args0 := []any{
		authRequest.ID,
		authRequest.ACR,
		authRequest.Expiration,
		authRequest.AuthTime,
		authRequest.ClientID,
		authRequest.Nonce,
		authRequest.RedirectURL,
		authRequest.ResponseType,
		authRequest.ResponseMode,
		authRequest.State,
		authRequest.Subject,
		authRequest.Challenge,
		authRequest.Remember,
		authRequest.Done,
	}
	err = d.execTx(tx, txCtx, "INSERT INTO oauth2_auth_request (id,acr,expiration,auth_time,client_id,nonce,redirect_url,response_type,response_mode,state,subject,challenge,remember,done) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)", args0...)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	for _, amr := range authRequest.AMR {
		err = d.execTx(tx, txCtx, "INSERT INTO oauth2_auth_request_amr (amr,auth_request_id) VALUES($1,$2)", amr, authRequest.ID)
		if err != nil {
			return d.rollbackTx(tx, err)
		}
	}
	for _, audience := range authRequest.Audience {
		err = d.execTx(tx, txCtx, "INSERT INTO oauth2_auth_request_audience (audience,auth_request_id) VALUES($1,$2)", audience, authRequest.ID)
		if err != nil {
			return d.rollbackTx(tx, err)
		}
	}
	if authRequest.CodeChallenge != nil {
		err = d.execTx(tx, txCtx, "INSERT INTO oauth2_auth_request_code_challenge (challenge,method,auth_request_id) VALUES($1,$2,$3)", authRequest.CodeChallenge.Challenge, authRequest.CodeChallenge.Method, authRequest.ID)
		if err != nil {
			return d.rollbackTx(tx, err)
		}
	}
	for _, scope := range authRequest.Scopes {
		err = d.execTx(tx, txCtx, "INSERT INTO oauth2_auth_request_scope (scope,auth_request_id) VALUES($1,$2)", scope, authRequest.ID)
		if err != nil {
			return d.rollbackTx(tx, err)
		}
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) SelectOAuth2AuthRequest(ctx context.Context, id string) (*OAuth2AuthRequest, error) {
	d.logger.Debug("selecting OAuth2 auth request", slog.String("id", id))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	authRequest, err := d.selectOAuth2AuthRequest(tx, txCtx, id)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectOAuth2AuthRequestAMRs(tx, txCtx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectOAuth2AuthRequestAudiences(tx, txCtx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectOAuth2AuthRequestCodeChallenge(tx, txCtx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectOAuth2AuthRequestScopes(tx, txCtx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return authRequest, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) selectOAuth2AuthRequest(tx *sql.Tx, txCtx context.Context, id string) (*OAuth2AuthRequest, error) {
	authRequest := NewOAuth2AuthRequest(id)
	row, err := d.queryRowTx(tx, txCtx, "SELECT acr,expiration,auth_time,client_id,nonce,redirect_url,response_type,response_mode,state,subject,challenge,remember,done FROM oauth2_auth_request WHERE id=$1", authRequest.ID)
	if err != nil {
		return nil, err
	}
	args := []any{
		&authRequest.ACR,
		&authRequest.Expiration,
		&authRequest.AuthTime,
		&authRequest.ClientID,
		&authRequest.Nonce,
		&authRequest.RedirectURL,
		&authRequest.ResponseType,
		&authRequest.ResponseMode,
		&authRequest.State,
		&authRequest.Subject,
		&authRequest.Challenge,
		&authRequest.Remember,
		&authRequest.Done,
	}
	err = row.Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w (unknown OAuth2 auth request: %s)", ErrObjectNotFound, authRequest.ID)
	} else if err != nil {
		return nil, fmt.Errorf("select OAuth2 auth request failure (cause: %w)", err)
	}
	return authRequest, nil
}

func (d *databaseDriver) selectOAuth2AuthRequestAMRs(tx *sql.Tx, txCtx context.Context, authRequest *OAuth2AuthRequest) error {
	rows, err := d.queryTx(tx, txCtx, "SELECT amr FROM oauth2_auth_request_amr WHERE auth_request_id=$1", authRequest.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var amr string
		err = rows.Scan(&amr)
		if err != nil {
			return fmt.Errorf("select OAuth2 auth request amr failure (cause: %w)", err)
		}
		authRequest.AMR = append(authRequest.AMR, amr)
	}
	return nil
}

func (d *databaseDriver) selectOAuth2AuthRequestAudiences(tx *sql.Tx, txCtx context.Context, authRequest *OAuth2AuthRequest) error {
	rows, err := d.queryTx(tx, txCtx, "SELECT audience FROM oauth2_auth_request_audience WHERE auth_request_id=$1", authRequest.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var audience string
		err = rows.Scan(&audience)
		if err != nil {
			return fmt.Errorf("select OAuth2 auth request audience failure (cause: %w)", err)
		}
		authRequest.Audience = append(authRequest.Audience, audience)
	}
	return nil
}

func (d *databaseDriver) selectOAuth2AuthRequestCodeChallenge(tx *sql.Tx, txCtx context.Context, authRequest *OAuth2AuthRequest) error {
	row, err := d.queryRowTx(tx, txCtx, "SELECT challenge,method FROM oauth2_auth_request_code_challenge WHERE auth_request_id=$1", authRequest.ID)
	if err != nil {
		return err
	}
	var challenge string
	var method oidc.CodeChallengeMethod
	err = row.Scan(&challenge, &method)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return fmt.Errorf("select OAuth2 auth request code challenge failure (cause: %w)", err)
	}
	authRequest.CodeChallenge = &oidc.CodeChallenge{
		Challenge: challenge,
		Method:    method,
	}
	return nil
}

func (d *databaseDriver) selectOAuth2AuthRequestScopes(tx *sql.Tx, txCtx context.Context, authRequest *OAuth2AuthRequest) error {
	rows, err := d.queryTx(tx, txCtx, "SELECT scope FROM oauth2_auth_request_scope WHERE auth_request_id=$1", authRequest.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var scope string
		err = rows.Scan(&scope)
		if err != nil {
			return fmt.Errorf("select OAuth2 auth request scope failure (cause: %w)", err)
		}
		authRequest.Scopes = append(authRequest.Scopes, scope)
	}
	return nil
}

func (d *databaseDriver) SelectOAuth2AuthRequestByCode(ctx context.Context, code string) (*OAuth2AuthRequest, error) {
	d.logger.Debug("selecting OAuth2 auth request id by auth code", slog.String("code", code))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	authRequest := NewOAuth2AuthRequest("")
	row, err := d.queryRowTx(tx, txCtx, "SELECT id,acr,expiration,auth_time,client_id,nonce,redirect_url,response_type,response_mode,state,subject,challenge,remember,done FROM oauth2_auth_request WHERE id IN (SELECT auth_request_id FROM oauth2_auth_code WHERE code=$1)", code)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	args := []any{
		&authRequest.ID,
		&authRequest.ACR,
		&authRequest.Expiration,
		&authRequest.AuthTime,
		&authRequest.ClientID,
		&authRequest.Nonce,
		&authRequest.RedirectURL,
		&authRequest.ResponseType,
		&authRequest.ResponseMode,
		&authRequest.State,
		&authRequest.Subject,
		&authRequest.Challenge,
		&authRequest.Remember,
		&authRequest.Done,
	}
	err = row.Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, d.rollbackTx(tx, fmt.Errorf("%w (unknown OAuth2 code request: %s)", ErrObjectNotFound, code))
	} else if err != nil {
		return nil, d.rollbackTx(tx, fmt.Errorf("select OAuth2 auth request by code failure (cause: %w)", err))
	}
	err = d.selectOAuth2AuthRequestAMRs(tx, txCtx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectOAuth2AuthRequestAudiences(tx, txCtx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectOAuth2AuthRequestCodeChallenge(tx, txCtx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectOAuth2AuthRequestScopes(tx, txCtx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return authRequest, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) AuthenticateOAuth2AuthRequest(ctx context.Context, id string, subject string, generateChallenge GenerateChallengeFunc, remember bool) error {
	d.logger.Debug("authenticating OAuth2 auth request", slog.String("id", id), slog.String("subject", subject))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	authRequest, err := d.selectOAuth2AuthRequest(tx, txCtx, id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	if authRequest.Subject != "" && authRequest.Subject != subject {
		return d.rollbackTx(tx, fmt.Errorf("non-matching OAuth auth request: %s != %s", authRequest.Subject, subject))
	}
	if authRequest.Challenge != "" {
		return d.rollbackTx(tx, fmt.Errorf("invalid OAuth2 auth request state: %s", authRequest.Challenge))
	}
	challenge, err := generateChallenge(ctx, subject)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	authRequest.Subject = subject
	authRequest.Challenge = challenge
	authRequest.Remember = remember
	args0 := []any{
		authRequest.Subject,
		authRequest.Challenge,
		authRequest.Remember,
		authRequest.ID,
	}
	err = d.execTx(tx, txCtx, "UPDATE oauth2_auth_request SET subject=$1,challenge=$2,remember=$3 WHERE id=$4", args0...)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) VerifyAndTransformOAuth2AuthRequestToUserSessionRequest(ctx context.Context, id string, subject string, verifyChallengeResponse VerifyChallengeResponseFunc, response string) (*UserSessionRequest, error) {
	d.logger.Debug("verifying and transforming OAuth2 auth request to user session request", slog.String("id", id))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	authRequest, err := d.selectOAuth2AuthRequest(tx, txCtx, id)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	if authRequest.Subject != subject {
		return nil, d.rollbackTx(tx, fmt.Errorf("non-matching OAuth auth request: %s != %s", authRequest.Subject, subject))
	}
	if authRequest.Expired() {
		// Verification failed (functionally)
		return nil, d.commitTx(tx, ctx == txCtx)
	}
	verified, err := verifyChallengeResponse(txCtx, authRequest.Subject, authRequest.Challenge, response)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	if !verified {
		// Verification failed (functionally)
		return nil, d.commitTx(tx, ctx == txCtx)
	}
	authRequest.AuthTime = time.Now().UnixMicro()
	authRequest.Done = true
	args0 := []any{
		authRequest.AuthTime,
		authRequest.Done,
		authRequest.ID,
	}
	err = d.execTx(tx, txCtx, "UPDATE oauth2_auth_request SET auth_time=$1,done=$2 WHERE id=$3", args0...)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	userSessionRequest := NewUserSessionRequest(authRequest.Subject, authRequest.Remember, authRequest.State)
	args1 := []any{
		userSessionRequest.ID,
		userSessionRequest.Subject,
		userSessionRequest.Remember,
		userSessionRequest.State,
		userSessionRequest.Expiration,
	}
	err = d.execTx(tx, txCtx, "INSERT INTO user_session_request (id,subject,remember,state,expiration) VALUES($1,$2,$3,$4,$5)", args1...)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return userSessionRequest, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) DeleteOAuth2AuthRequest(ctx context.Context, id string) error {
	d.logger.Debug("deleting OAuth2 auth request", slog.String("id", id))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_code WHERE auth_request_id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_request_scope WHERE auth_request_id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_request_code_challenge WHERE auth_request_id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_request_audience WHERE auth_request_id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_request_amr WHERE auth_request_id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_request WHERE id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) DeleteExpiredOAuth2AuthRequests(ctx context.Context) error {
	d.logger.Debug("deleting expired OAuth2 auth requests")
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UnixMicro()
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_code WHERE auth_request_id IN (SELECT id FROM oauth2_auth_request WHERE expiration < $1)", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_request_scope WHERE auth_request_id IN (SELECT id FROM oauth2_auth_request WHERE expiration < $1)", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_request_code_challenge WHERE auth_request_id IN (SELECT id FROM oauth2_auth_request WHERE expiration < $1)", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_request_audience WHERE auth_request_id IN (SELECT id FROM oauth2_auth_request WHERE expiration < $1)", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_request_amr WHERE auth_request_id IN (SELECT id FROM oauth2_auth_request WHERE expiration < $1)", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_auth_request WHERE expiration < $1", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) InsertOAuth2AuthCode(ctx context.Context, code string, id string) error {
	d.logger.Debug("inserting OAuth2 auth code", slog.String("code", code))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	args := []any{
		code,
		id,
	}
	err = d.execTx(tx, txCtx, "INSERT INTO oauth2_auth_code (code,auth_request_id) VALUES($1,$2)", args...)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) InsertOAuth2Token(ctx context.Context, token *OAuth2Token) error {
	d.logger.Debug("inserting OAuth2 token", slog.String("id", token.ID))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	err = d.insertOAuth2Token(tx, txCtx, token)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) insertOAuth2Token(tx *sql.Tx, txCtx context.Context, token *OAuth2Token) error {
	args0 := []any{
		token.ID,
		token.ClientID,
		token.Subject,
		token.RefreshTokenID,
		token.Expiration,
	}
	err := d.execTx(tx, txCtx, "INSERT INTO oauth2_token (id,client_id,subject,refresh_token_id,expiration) VALUES($1,$2,$3,$4,$5)", args0...)
	if err != nil {
		return err
	}
	for _, audience := range token.Audience {
		err = d.execTx(tx, txCtx, "INSERT INTO oauth2_token_audience (audience,token_id) VALUES($1,$2)", audience, token.ID)
		if err != nil {
			return err
		}
	}
	for _, scope := range token.Scopes {
		err = d.execTx(tx, txCtx, "INSERT INTO oauth2_token_scope (scope,token_id) VALUES($1,$2)", scope, token.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *databaseDriver) SelectOAuth2Token(ctx context.Context, id string) (*OAuth2Token, error) {
	d.logger.Debug("selecting OAuth2 token", slog.String("id", id))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	token := NewOAuth2Token(id)
	row, err := d.queryRowTx(tx, txCtx, "SELECT client_id,subject,refresh_token_id,expiration FROM oauth2_token WHERE id=$1", token.ID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	args0 := []any{
		&token.ClientID,
		&token.Subject,
		&token.RefreshTokenID,
		&token.Expiration,
	}
	err = row.Scan(args0...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, d.rollbackTx(tx, fmt.Errorf("%w (unknown OAuth2 token: %s)", ErrObjectNotFound, token.ID))
	} else if err != nil {
		return nil, d.rollbackTx(tx, fmt.Errorf("select OAuth2 token failure (cause: %w)", err))
	}
	rows1, err := d.queryTx(tx, txCtx, "SELECT audience FROM oauth2_token_audience WHERE token_id=$1", token.ID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	defer rows1.Close()
	for rows1.Next() {
		var audience string
		err = rows1.Scan(&audience)
		if err != nil {
			return nil, d.rollbackTx(tx, fmt.Errorf("select OAuth2 token audience failure (cause: %w)", err))
		}
		token.Audience = append(token.Audience, audience)
	}
	rows1.Close()
	rows2, err := d.queryTx(tx, txCtx, "SELECT scope FROM oauth2_token_scope WHERE token_id=$1", token.ID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var scope string
		err = rows2.Scan(&scope)
		if err != nil {
			return nil, d.rollbackTx(tx, fmt.Errorf("select OAuth2 token scope failure (cause: %w)", err))
		}
		token.Scopes = append(token.Scopes, scope)
	}
	rows2.Close()
	return token, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) DeleteOAuth2Token(ctx context.Context, id string) error {
	d.logger.Debug("deleting OAuth2 token", slog.String("id", id))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	err = d.deleteOAuth2RefreshTokensByTokenID(tx, txCtx, id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.deleteOAuth2Token(tx, txCtx, id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) DeleteExpiredOAuth2Tokens(ctx context.Context) error {
	d.logger.Debug("deleting expired OAuth2 tokens")
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UnixMicro()
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_token_scope WHERE token_id IN (SELECT id FROM oauth2_token WHERE expiration < $1 AND id NOT IN (SELECT access_token_id FROM oauth2_refresh_token))", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_token_audience WHERE token_id IN (SELECT id FROM oauth2_token WHERE expiration < $1 AND id NOT IN (SELECT access_token_id FROM oauth2_refresh_token))", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_token WHERE expiration < $1 AND id NOT IN (SELECT access_token_id FROM oauth2_refresh_token)", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) deleteOAuth2Token(tx *sql.Tx, txCtx context.Context, id string) error {
	err := d.execTx(tx, txCtx, "DELETE FROM oauth2_token_scope WHERE token_id=$1", id)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_token_audience WHERE token_id=$1", id)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_token WHERE id=$1", id)
	if err != nil {
		return err
	}
	return nil
}

func (d *databaseDriver) deleteOAuth2TokenByRefreshTokenID(tx *sql.Tx, txCtx context.Context, refreshTokenID string) error {
	err := d.execTx(tx, txCtx, "DELETE FROM oauth2_token_scope WHERE token_id IN (SELECT id FROM oauth2_token WHERE refresh_token_id=$1)", refreshTokenID)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_token_audience WHERE token_id IN (SELECT id FROM oauth2_token WHERE refresh_token_id=$1)", refreshTokenID)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_token WHERE refresh_token_id=$1", refreshTokenID)
	if err != nil {
		return err
	}
	return nil
}

func (d *databaseDriver) InsertOAuth2RefreshToken(ctx context.Context, refreshToken *OAuth2RefreshToken, token *OAuth2Token) error {
	d.logger.Debug("inserting OAuth2 refresh token", slog.String("id", refreshToken.ID))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	err = d.insertOAuth2Token(tx, txCtx, token)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.insertOAuth2RefreshToken(tx, txCtx, refreshToken)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) insertOAuth2RefreshToken(tx *sql.Tx, txCtx context.Context, refreshToken *OAuth2RefreshToken) error {
	args0 := []any{
		refreshToken.ID,
		refreshToken.AuthTime,
		refreshToken.Subject,
		refreshToken.ClientID,
		refreshToken.Expiration,
		refreshToken.AccessTokenID,
	}
	err := d.execTx(tx, txCtx, "INSERT INTO oauth2_refresh_token (id,auth_time,subject,client_id,expiration,access_token_id) VALUES($1,$2,$3,$4,$5,$6)", args0...)
	if err != nil {
		return err
	}
	for _, amr := range refreshToken.AMR {
		err = d.execTx(tx, txCtx, "INSERT INTO oauth2_refresh_token_amr (amr,refresh_token_id) VALUES($1,$2)", amr, refreshToken.ID)
		if err != nil {
			return err
		}
	}
	for _, audience := range refreshToken.Audience {
		err = d.execTx(tx, txCtx, "INSERT INTO oauth2_refresh_token_audience (audience,refresh_token_id) VALUES($1,$2)", audience, refreshToken.ID)
		if err != nil {
			return err
		}
	}
	for _, scope := range refreshToken.Scopes {
		err = d.execTx(tx, txCtx, "INSERT INTO oauth2_refresh_token_scope (scope,refresh_token_id) VALUES($1,$2)", scope, refreshToken.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *databaseDriver) RenewOAuth2RefreshToken(ctx context.Context, id string, newToken *OAuth2Token) (*OAuth2RefreshToken, error) {
	d.logger.Debug("renewing OAuth2 refresh token", slog.String("id", id))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	oldRefreshToken, err := d.selectOAuth2RefreshToken(tx, txCtx, id)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	newRefreshToken := NewOAuth2RefreshTokenFromRefreshToken(newToken.RefreshTokenID, newToken.ID, oldRefreshToken)
	err = d.deleteOAuth2RefreshToken(tx, txCtx, oldRefreshToken.ID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.deleteOAuth2Token(tx, txCtx, oldRefreshToken.AccessTokenID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.insertOAuth2Token(tx, txCtx, newToken)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.insertOAuth2RefreshToken(tx, txCtx, newRefreshToken)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return newRefreshToken, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) deleteOAuth2RefreshToken(tx *sql.Tx, txCtx context.Context, id string) error {
	err := d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_scope WHERE refresh_token_id=$1", id)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_audience WHERE refresh_token_id=$1", id)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_amr WHERE refresh_token_id=$1", id)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token WHERE id=$1", id)
	if err != nil {
		return err
	}
	return nil
}

func (d *databaseDriver) SelectOAuth2RefreshToken(ctx context.Context, id string) (*OAuth2RefreshToken, error) {
	d.logger.Debug("selecting OAuth2 refresh token", slog.String("id", id))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	refreshToken, err := d.selectOAuth2RefreshToken(tx, txCtx, id)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return refreshToken, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) selectOAuth2RefreshToken(tx *sql.Tx, txCtx context.Context, id string) (*OAuth2RefreshToken, error) {
	refreshToken := NewOAuth2RefreshToken(id)
	row, err := d.queryRowTx(tx, txCtx, "SELECT auth_time,subject,client_id,expiration,access_token_id FROM oauth2_refresh_token WHERE id=$1", refreshToken.ID)
	if err != nil {
		return nil, err
	}
	args := []any{
		&refreshToken.AuthTime,
		&refreshToken.Subject,
		&refreshToken.ClientID,
		&refreshToken.Expiration,
		&refreshToken.AccessTokenID,
	}
	err = row.Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w (unknown OAuth2 refresh token: %s)", ErrObjectNotFound, refreshToken.ID)
	} else if err != nil {
		return nil, fmt.Errorf("select OAuth2 refresh token failure (cause: %w)", err)
	}
	err = d.selectOAuth2RefreshTokenAMRs(tx, txCtx, refreshToken)
	if err != nil {
		return nil, err
	}
	err = d.selectOAuth2RefreshTokenAudiences(tx, txCtx, refreshToken)
	if err != nil {
		return nil, err
	}
	err = d.selectOAuth2RefreshTokenScopes(tx, txCtx, refreshToken)
	if err != nil {
		return nil, err
	}
	return refreshToken, nil
}

func (d *databaseDriver) selectOAuth2RefreshTokenAMRs(tx *sql.Tx, txCtx context.Context, refreshToken *OAuth2RefreshToken) error {
	rows, err := d.queryTx(tx, txCtx, "SELECT amr FROM oauth2_refresh_token_amr WHERE refresh_token_id=$1", refreshToken.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var amr string
		err = rows.Scan(&amr)
		if err != nil {
			return fmt.Errorf("select OAuth2 refresh token amr failure (cause: %w)", err)
		}
		refreshToken.AMR = append(refreshToken.AMR, amr)
	}
	return nil
}

func (d *databaseDriver) selectOAuth2RefreshTokenAudiences(tx *sql.Tx, txCtx context.Context, refreshToken *OAuth2RefreshToken) error {
	rows, err := d.queryTx(tx, txCtx, "SELECT audience FROM oauth2_refresh_token_audience WHERE refresh_token_id=$1", refreshToken.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var audience string
		err = rows.Scan(&audience)
		if err != nil {
			return fmt.Errorf("select OAuth2 refresh token audience failure (cause: %w)", err)
		}
		refreshToken.Audience = append(refreshToken.Audience, audience)
	}
	return nil
}

func (d *databaseDriver) selectOAuth2RefreshTokenScopes(tx *sql.Tx, txCtx context.Context, refreshToken *OAuth2RefreshToken) error {
	rows, err := d.queryTx(tx, txCtx, "SELECT scope FROM oauth2_refresh_token_scope WHERE refresh_token_id=$1", refreshToken.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var scope string
		err = rows.Scan(&scope)
		if err != nil {
			return fmt.Errorf("select OAuth2 refresh token scope failure (cause: %w)", err)
		}
		refreshToken.Scopes = append(refreshToken.Scopes, scope)
	}
	return nil
}

func (d *databaseDriver) DeleteOAuth2TokensBySubject(ctx context.Context, applicationID string, subject string) error {
	d.logger.Debug("deleting OAuth2 tokens by subject", slog.String("applicationID", applicationID), slog.String("subject", subject))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	err = d.deleteOAuth2RefreshTokensByTokenSubject(tx, txCtx, applicationID, subject)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.deleteOAuth2TokensBySubject(tx, txCtx, applicationID, subject)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) deleteOAuth2RefreshTokensByTokenSubject(tx *sql.Tx, txCtx context.Context, applicationID string, subject string) error {
	err := d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_scope WHERE refresh_token_id IN (SELECT id FROM oauth2_refresh_token WHERE access_token_id IN (SELECT id FROM oauth2_token WHERE client_id=$1 AND subject=$2))", applicationID, subject)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_audience WHERE refresh_token_id IN (SELECT id FROM oauth2_refresh_token WHERE access_token_id IN (SELECT id FROM oauth2_token WHERE client_id=$1 AND subject=$2))", applicationID, subject)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_amr WHERE refresh_token_id IN (SELECT id FROM oauth2_refresh_token WHERE access_token_id IN (SELECT id FROM oauth2_token WHERE client_id=$1 AND subject=$2))", applicationID, subject)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token WHERE access_token_id IN (SELECT id FROM oauth2_token WHERE client_id=$1 AND subject=$2)", applicationID, subject)
	if err != nil {
		return err
	}
	return nil
}

func (d *databaseDriver) deleteOAuth2TokensBySubject(tx *sql.Tx, txCtx context.Context, applicationID string, subject string) error {
	err := d.execTx(tx, txCtx, "DELETE FROM oauth2_token_scope WHERE token_id IN (SELECT id FROM oauth2_token WHERE client_id=$1 AND subject=$2)", applicationID, subject)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_token_audience WHERE token_id IN (SELECT id FROM oauth2_token WHERE client_id=$1 AND subject=$2)", applicationID, subject)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_token WHERE client_id=$1 AND subject=$2", applicationID, subject)
	if err != nil {
		return err
	}
	return nil
}

func (d *databaseDriver) DeleteOAuth2RefreshToken(ctx context.Context, id string) error {
	d.logger.Debug("deleting OAuth2 refresh token", slog.String("id", id))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	err = d.deleteOAuth2RefreshToken(tx, txCtx, id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.deleteOAuth2TokenByRefreshTokenID(tx, txCtx, id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) deleteOAuth2RefreshTokensByTokenID(tx *sql.Tx, txCtx context.Context, tokenID string) error {
	err := d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_scope WHERE refresh_token_id IN (SELECT id FROM oauth2_refresh_token WHERE access_token_id IN (SELECT id FROM oauth2_token WHERE id=$1))", tokenID)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_audience WHERE refresh_token_id IN (SELECT id FROM oauth2_refresh_token WHERE access_token_id IN (SELECT id FROM oauth2_token WHERE id=$1))", tokenID)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_amr WHERE refresh_token_id IN (SELECT id FROM oauth2_refresh_token WHERE access_token_id IN (SELECT id FROM oauth2_token WHERE id=$1))", tokenID)
	if err != nil {
		return err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token WHERE access_token_id IN (SELECT id FROM oauth2_token WHERE id=$1)", tokenID)
	if err != nil {
		return err
	}
	return nil
}

func (d *databaseDriver) DeleteExpiredOAuth2RefreshTokens(ctx context.Context) error {
	d.logger.Debug("deleting expired OAuth2 refresh tokens")
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UnixMicro()
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_scope WHERE refresh_token_id IN (SELECT id FROM oauth2_refresh_token WHERE expiration < $1)", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_audience WHERE refresh_token_id IN (SELECT id FROM oauth2_refresh_token WHERE expiration < $1)", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token_amr WHERE refresh_token_id IN (SELECT id FROM oauth2_refresh_token WHERE expiration < $1)", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, txCtx, "DELETE FROM oauth2_refresh_token WHERE expiration < $1", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) RotateSigningKeys(ctx context.Context, algorithm string, generateSigningKey GenerateSigningKeyFunc) (SigningKeys, error) {
	d.logger.Debug("rotating signing keys")
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMicro()
	// Delete expired keys
	err = d.execTx(tx, txCtx, "DELETE FROM signing_key WHERE expiration<$1", now)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	// Select current keys and check for current key
	signingKeys, err := d.selectSigningKeys(tx, ctx)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	var activeSigningKey *SigningKey
	for _, signingKey := range signingKeys {
		if signingKey.Algorithm != algorithm {
			continue
		}
		if now <= signingKey.Passivation {
			activeSigningKey = signingKey
		}
		break
	}
	// Finished, if active signing key is in place
	if activeSigningKey != nil {
		return signingKeys, d.commitTx(tx, ctx == txCtx)
	}
	// Generate and insert new key
	newSigningKey, err := generateSigningKey(algorithm)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	args := []any{
		newSigningKey.ID,
		newSigningKey.Algorithm,
		newSigningKey.PrivateKey,
		newSigningKey.PublicKey,
		newSigningKey.Passivation,
		newSigningKey.Expiration,
	}
	err = d.execTx(tx, txCtx, "INSERT INTO signing_key (id,algorithm,private_key,public_key,passivation,expiration) VALUES($1,$2,$3,$4,$5,$6)", args...)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	// Re-select all keys
	signingKeys, err = d.selectSigningKeys(tx, ctx)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return signingKeys, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) selectSigningKeys(tx *sql.Tx, txCtx context.Context) (SigningKeys, error) {
	rows, err := d.queryTx(tx, txCtx, "SELECT id,algorithm,private_key,public_key,passivation,expiration FROM signing_key ORDER BY passivation,expiration DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	signingKeys := SigningKeys(make([]*SigningKey, 0))
	for rows.Next() {
		signingKey := &SigningKey{}
		args := []any{
			&signingKey.ID,
			&signingKey.Algorithm,
			&signingKey.PrivateKey,
			&signingKey.PublicKey,
			&signingKey.Passivation,
			&signingKey.Expiration,
		}
		err = rows.Scan(args...)
		if err != nil {
			return nil, fmt.Errorf("select signing key failure (cause: %w)", err)
		}
		signingKeys = append(signingKeys, signingKey)
	}
	return signingKeys, nil
}

func (d *databaseDriver) TransformAndDeleteUserSessionRequest(ctx context.Context, state string, token *oauth2.Token) (*UserSession, error) {
	d.logger.Debug("transforming user session request", slog.String("state", state))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	request, err := d.selectUserSessionRequestByState(tx, txCtx, state)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	if request.Expired() {
		// Transformation failed (functionally)
		return nil, d.commitTx(tx, ctx == txCtx)
	}
	session := NewUserSession(token, request.Subject, request.Remember)
	args := []any{
		session.ID,
		session.Subject,
		session.Remember,
		session.AccessToken,
		session.TokenType,
		session.RefreshToken,
		session.Expiration,
	}
	err = d.execTx(tx, txCtx, "INSERT INTO user_session (id,subject,remember,access_token,token_type,refresh_token,expiration) VALUES($1,$2,$3,$4,$5,$6,$7)", args...)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return session, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) selectUserSessionRequestByState(tx *sql.Tx, txCtx context.Context, state string) (*UserSessionRequest, error) {
	userSessionRequest := &UserSessionRequest{
		State: state,
	}
	row, err := d.queryRowTx(tx, txCtx, "SELECT id,subject,remember,expiration FROM user_session_request WHERE state=$1", userSessionRequest.State)
	if err != nil {
		return nil, err
	}
	args := []any{
		&userSessionRequest.ID,
		&userSessionRequest.Subject,
		&userSessionRequest.Remember,
		&userSessionRequest.Expiration,
	}
	err = row.Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w (unknown user session request state: %s)", ErrObjectNotFound, userSessionRequest.State)
	} else if err != nil {
		return nil, fmt.Errorf("select user session request failure (cause: %w)", err)
	}
	return userSessionRequest, nil
}

func (d *databaseDriver) DeleteExpiredUserSessionRequests(ctx context.Context) error {
	d.logger.Debug("deleting expired user session requests")
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UnixMicro()
	err = d.execTx(tx, txCtx, "DELETE FROM user_session_request WHERE expiration < $1", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) SelectUserSession(ctx context.Context, id string) (*UserSession, error) {
	d.logger.Debug("selecting user session", slog.String("id", id))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	userSession := &UserSession{
		ID: id,
	}
	row, err := d.queryRowTx(tx, txCtx, "SELECT subject,remember,access_token,token_type,refresh_token,expiration FROM user_session WHERE id=$1", userSession.ID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	args := []any{
		&userSession.Subject,
		&userSession.Remember,
		&userSession.AccessToken,
		&userSession.TokenType,
		&userSession.RefreshToken,
		&userSession.Expiration,
	}
	err = row.Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, d.rollbackTx(tx, fmt.Errorf("%w (unknown user session: %s)", ErrObjectNotFound, userSession.ID))
	} else if err != nil {
		return nil, d.rollbackTx(tx, fmt.Errorf("select user session failure (cause: %w)", err))
	}
	return userSession, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) InsertOrUpdateUserVerificationLog(ctx context.Context, log *UserVerificationLog) (*UserVerificationLog, error) {
	d.logger.Debug("inserting/updating user verification log", slog.String("subject", log.Subject), slog.String("method", log.Method))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	updatedLog := &UserVerificationLog{
		Subject: log.Subject,
		Method:  log.Method,
	}
	row, err := d.queryRowTx(tx, txCtx, "SELECT first_used FROM user_verification_log WHERE subject=$1 AND method=$2", updatedLog.Subject, updatedLog.Method)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	args0 := []any{
		&updatedLog.FirstUsed,
	}
	err = row.Scan(args0...)
	if errors.Is(err, sql.ErrNoRows) {
		updatedLog = log
		args1 := []any{
			updatedLog.Subject,
			updatedLog.Method,
			updatedLog.FirstUsed,
			updatedLog.LastUsed,
			updatedLog.Host,
			updatedLog.Country,
			updatedLog.CountryCode,
			updatedLog.City,
			updatedLog.Lat,
			updatedLog.Lon,
		}
		err = d.execTx(tx, txCtx, "INSERT INTO user_verification_log (subject,method,first_used,last_used,host,country,country_code,city,lat,lon) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", args1...)
		if err != nil {
			return nil, d.rollbackTx(tx, fmt.Errorf("insert user verification log failure (cause: %w)", err))
		}
	} else if err != nil {
		return nil, d.rollbackTx(tx, fmt.Errorf("select user verification log failure (cause: %w)", err))
	} else {
		updatedLog.Update(log)
		args2 := []any{
			updatedLog.FirstUsed,
			updatedLog.LastUsed,
			updatedLog.Host,
			updatedLog.Country,
			updatedLog.CountryCode,
			updatedLog.City,
			updatedLog.Lat,
			updatedLog.Lon,
			updatedLog.Subject,
			updatedLog.Method,
		}
		err = d.execTx(tx, txCtx, "UPDATE user_verification_log SET first_used=$1,last_used=$2,host=$3,country=$4,country_code=$5,city=$6,lat=$7,lon=$8 WHERE subject=$9 AND method=$10", args2...)
		if err != nil {
			return nil, d.rollbackTx(tx, fmt.Errorf("update user verification log failure (cause: %w)", err))
		}
	}
	return log, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) SelectUserVerificationLogs(ctx context.Context, subject string) ([]*UserVerificationLog, error) {
	d.logger.Debug("selecting user verification logs", slog.String("subject", subject))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := d.queryTx(tx, txCtx, "SELECT method,first_used,last_used,host,country,country_code,city,lat,lon FROM user_verification_log WHERE subject=$1", subject)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	defer rows.Close()
	logs := make([]*UserVerificationLog, 0, 4)
	for rows.Next() {
		log := &UserVerificationLog{
			Subject: subject,
		}
		args := []any{
			&log.Method,
			&log.FirstUsed,
			&log.LastUsed,
			&log.Host,
			&log.Country,
			&log.CountryCode,
			&log.City,
			&log.Lat,
			&log.Lon,
		}
		err = rows.Scan(args...)
		if err != nil {
			return nil, d.rollbackTx(tx, fmt.Errorf("select user verification log failure (cause: %w)", err))
		}
		logs = append(logs, log)
	}
	return logs, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) deleteUserVerificationLog(tx *sql.Tx, txCtx context.Context, subject string, method string) error {
	err := d.execTx(tx, txCtx, "DELETE FROM user_verification_log WHERE subject=$1 AND method=$2", subject, method)
	if err != nil {
		return err
	}
	return nil
}

func (d *databaseDriver) GenerateUserTOTPRegistrationRequest(ctx context.Context, subject string, secret string, generateChallengeFunc GenerateChallengeFunc) (*UserTOTPRegistrationRequest, error) {
	d.logger.Debug("generating user TOTP registration request", slog.String("subject", subject))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	err = d.execTx(tx, txCtx, "DELETE FROM user_totp_registration_request WHERE subject=$1", subject)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	challenge, err := generateChallengeFunc(txCtx, subject)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	request := NewUserTOTPRegistrationRequest(subject, secret, challenge)
	args := []any{
		request.Subject,
		request.Secret,
		request.Challenge,
		request.Expiration,
	}
	err = d.execTx(tx, txCtx, "INSERT INTO user_totp_registration_request (subject,secret,challenge,expiration) VALUES($1,$2,$3,$4)", args...)
	if err != nil {
		return nil, d.rollbackTx(tx, fmt.Errorf("insert user TOTP registration request failure (cause: %w)", err))
	}
	return request, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) SelectUserTOTPRegistrationRequest(ctx context.Context, subject string) (*UserTOTPRegistrationRequest, error) {
	d.logger.Debug("selecting user TOTP registration request", slog.String("subject", subject))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	request, err := d.selectUserTOTPRegistrationRequest(tx, txCtx, subject)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return request, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) selectUserTOTPRegistrationRequest(tx *sql.Tx, txCtx context.Context, subject string) (*UserTOTPRegistrationRequest, error) {
	request := &UserTOTPRegistrationRequest{
		Subject: subject,
	}
	row, err := d.queryRowTx(tx, txCtx, "SELECT secret,challenge,expiration FROM user_totp_registration_request WHERE subject=$1", request.Subject)
	if err != nil {
		return nil, err
	}
	args := []any{
		&request.Secret,
		&request.Challenge,
		&request.Expiration,
	}
	err = row.Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w (unknown user TOTP registration request: %s)", ErrObjectNotFound, request.Subject)
	} else if err != nil {
		return nil, fmt.Errorf("select user TOTP registration request failure (cause: %w)", err)
	}
	return request, nil
}

func (d *databaseDriver) DeleteExpiredUserTOTPRegistrationRequests(ctx context.Context) error {
	d.logger.Debug("deleting expired user TOTP registration requests")
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UnixMicro()
	err = d.execTx(tx, txCtx, "DELETE FROM user_totp_registration_request WHERE expiration < $1", now)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) VerifyAndTransformUserTOTPRegistrationRequestToRegistration(ctx context.Context, subject string, verifyChallengeResponse VerifyChallengeResponseFunc, response string) (*UserTOTPRegistration, error) {
	d.logger.Debug("verifying and transforming user TOTP registration request", slog.String("subject", subject))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	request, err := d.selectUserTOTPRegistrationRequest(tx, txCtx, subject)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	if request.Expired() {
		// Verification failed (functionally)
		return nil, d.commitTx(tx, ctx == txCtx)
	}
	err = d.deleteUserVerificationLog(tx, txCtx, subject, TOTPKey)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	verified, err := verifyChallengeResponse(txCtx, subject, request.Challenge, response)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	if !verified {
		// Verification failed (functionally)
		return nil, d.commitTx(tx, ctx == txCtx)
	}
	err = d.deleteUserTOTPRegistration(tx, txCtx, subject)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	registration := NewUserTOTPRegistrationFromRequest(request)
	args := []any{
		registration.Subject,
		registration.Secret,
		registration.CreateTime,
	}
	err = d.execTx(tx, txCtx, "INSERT INTO user_totp_registration (subject,secret,create_time) VALUES($1,$2,$3)", args...)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return registration, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) deleteUserTOTPRegistration(tx *sql.Tx, txCtx context.Context, subject string) error {
	return d.execTx(tx, txCtx, "DELETE FROM user_totp_registration WHERE subject=$1", subject)
}

func (d *databaseDriver) SelectUserTOTPRegistration(ctx context.Context, subject string) (*UserTOTPRegistration, error) {
	d.logger.Debug("selecting user TOTP registration", slog.String("subject", subject))
	tx, txCtx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	registration := &UserTOTPRegistration{
		Subject: subject,
	}
	row, err := d.queryRowTx(tx, txCtx, "SELECT secret,create_time FROM user_totp_registration WHERE subject=$1", registration.Subject)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	args := []any{
		&registration.Secret,
		&registration.CreateTime,
	}
	err = row.Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w (unknown user TOTP registration: %s)", ErrObjectNotFound, registration.Subject)
	} else if err != nil {
		return nil, fmt.Errorf("select user TOTP registration failure (cause: %w)", err)
	}
	return registration, d.commitTx(tx, ctx == txCtx)
}

func (d *databaseDriver) Close() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	for _, stmt := range d.stmts {
		err := stmt.Close()
		if err != nil {
			d.logger.Warn("failed to close db statement", slog.Any("err", err))
		}
	}
	return d.db.Close()
}

func (d *databaseDriver) beginTx(ctx context.Context) (*sql.Tx, context.Context, error) {
	tx, nestedTx := ctx.Value(d).(*sql.Tx)
	if nestedTx {
		return tx, ctx, nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin transaction failure (cause: %w)", err)
	}
	txCtx := context.WithValue(ctx, d, tx)
	return tx, txCtx, nil
}

func (d *databaseDriver) rollbackTx(tx *sql.Tx, err error) error {
	rollbackErr := tx.Rollback()
	if rollbackErr != nil {
		d.logger.Warn("rollback failure", slog.Any("err", err))
	}
	return errors.Join(err, rollbackErr)
}

func (d *databaseDriver) commitTx(tx *sql.Tx, nestedTx bool) error {
	if nestedTx {
		return nil
	}
	err := tx.Commit()
	if err != nil {
		return fmt.Errorf("commit failure (cause: %w)", err)
	}
	return nil
}

func (d *databaseDriver) execTx(tx *sql.Tx, txCtx context.Context, query string, args ...any) error {
	d.logger.Debug("sql exec", slog.String("query", query))
	stmt, err := d.prepareStmt(txCtx, query)
	if err != nil {
		return err
	}
	txStmt := tx.StmtContext(txCtx, stmt)
	result, err := txStmt.ExecContext(txCtx, args...)
	if err != nil {
		return fmt.Errorf("sql exec failure (cause: %w)", err)
	}
	rows, err := result.RowsAffected()
	if err == nil {
		d.logger.Debug("sql exec complete", slog.Int64("rows", rows))
	}
	return nil
}

func (d *databaseDriver) queryRowTx(tx *sql.Tx, txCtx context.Context, query string, args ...any) (*sql.Row, error) {
	d.logger.Debug("sql query", slog.String("query", query))
	stmt, err := d.prepareStmt(txCtx, query)
	if err != nil {
		return nil, err
	}
	txStmt := tx.StmtContext(txCtx, stmt)
	return txStmt.QueryRowContext(txCtx, args...), nil
}

func (d *databaseDriver) queryTx(tx *sql.Tx, txCtx context.Context, query string, args ...any) (*sql.Rows, error) {
	d.logger.Debug("sql query", slog.String("query", query))
	stmt, err := d.prepareStmt(txCtx, query)
	if err != nil {
		return nil, err
	}
	txStmt := tx.StmtContext(txCtx, stmt)
	rows, err := txStmt.QueryContext(txCtx, args...)
	if err != nil {
		return nil, fmt.Errorf("sql query failure (cause: %w)", err)
	}
	return rows, nil
}

func (d *databaseDriver) prepareStmt(ctx context.Context, query string) (*sql.Stmt, error) {
	stmt := func() *sql.Stmt {
		d.mutex.RLock()
		defer d.mutex.RUnlock()
		return d.stmts[query]
	}()
	if stmt != nil {
		return stmt, nil
	}
	return func() (*sql.Stmt, error) {
		d.mutex.Lock()
		defer d.mutex.Unlock()
		stmt, err := d.db.PrepareContext(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare statement: '%s' (cause: %w)", query, err)
		}
		d.stmts[query] = stmt
		return stmt, nil
	}()
}

func (d *databaseDriver) runScriptTx(tx *sql.Tx, txCtx context.Context, script []byte) error {
	reader, err := newSQLScriptReader(script)
	if err != nil {
		return err
	}
	for {
		statement, err := reader.readStatement()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		d.logger.Debug("script exec", slog.String("statement", statement))
		result, err := tx.ExecContext(txCtx, statement)
		if err != nil {
			return fmt.Errorf("script exec failure at %d (cause: %w)", reader.LineNo(), err)
		}
		rows, err := result.RowsAffected()
		if err == nil {
			d.logger.Debug("script exec complete", slog.Int64("rows", rows))
		}
	}
}

type sqlScriptReader struct {
	reader *bufio.Reader
	lineNo int
}

func newSQLScriptReader(script []byte) (*sqlScriptReader, error) {
	reader := bufio.NewReader(bytes.NewReader(script))
	r := &sqlScriptReader{
		reader: reader,
	}
	return r, nil
}

func (r *sqlScriptReader) LineNo() int {
	return r.lineNo
}

func (r *sqlScriptReader) readStatement() (string, error) {
	statement := ""
	for {
		line, excessive, err := r.reader.ReadLine()
		if errors.Is(err, io.EOF) {
			if statement != "" {
				return statement, fmt.Errorf("incomplete statement at %d", r.lineNo)
			}
			return statement, err
		} else if err != nil {
			return statement, fmt.Errorf("failed to read script (cause: %w)", err)
		}
		r.lineNo++
		if excessive {
			return statement, fmt.Errorf("excessive line length at %d", r.lineNo)
		}
		lineString := strings.TrimSpace(string(line))
		if statement != "" {
			statement = statement + " " + lineString
		} else {
			statement = lineString
		}
		if strings.HasSuffix(lineString, ";") {
			return statement, nil
		}
	}
}
