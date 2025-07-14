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
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

type Driver interface {
	Name() string
	UpdateSchema(ctx context.Context) (SchemaVersion, SchemaVersion, error)
	InsertAuthRequest(ctx context.Context, authRequest *AuthRequest) error
	SelectAuthRequest(ctx context.Context, id string) (*AuthRequest, error)
	SelectAuthRequestByCode(ctx context.Context, code string) (*AuthRequest, error)
	AuthenticateAndTransformAuthRequestToUserSessionRequest(ctx context.Context, id string, email string, remember bool) (*UserSessionRequest, error)
	DeleteAuthRequest(ctx context.Context, id string) error
	InsertAuthCode(ctx context.Context, code string, id string) error
	InsertToken(ctx context.Context, token *Token) error
	SelectToken(ctx context.Context, id string) (*Token, error)
	InsertRefreshToken(ctx context.Context, refreshToken *RefreshToken, token *Token) error
	RenewRefreshToken(ctx context.Context, id string, newToken *Token) (*RefreshToken, error)
	SelectRefreshToken(ctx context.Context, id string) (*RefreshToken, error)
	RotateSigningKeys(ctx context.Context, algorithm string, generateSigningKey func(string) (*SigningKey, error)) (SigningKeys, error)
	TransformAndDeleteUserSessionRequest(ctx context.Context, state string, token *oauth2.Token) (*UserSession, error)
	SelectUserSession(ctx context.Context, id string) (*UserSession, error)
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
		logger:  logger,
		scripts: scripts,
	}
	return d, nil
}

var ErrObjectNotFound = errors.New("object not found")

type databaseDriver struct {
	name    string
	db      *sql.DB
	logger  *slog.Logger
	scripts [][]byte
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
	tx, err := d.beginTx(ctx)
	if err != nil {
		return SchemaNone, SchemaNone, err
	}
	switch fromVersion {
	case SchemaNone:
		d.logger.Debug("running schema1 update script")
		err = d.runScriptTx(tx, ctx, d.scripts[0])
	case Schema1:
		// Nothing to do
		d.logger.Debug("schema already up-to-date; no update required")
	default:
		err = fmt.Errorf("unrecognized database schema version: %s", fromVersion)
	}
	if err != nil {
		return SchemaNone, SchemaNone, d.rollbackTx(tx, err)
	}
	return fromVersion, Schema1, d.commitTx(tx)
}

func (d *databaseDriver) querySchemaVersion(ctx context.Context) (SchemaVersion, error) {
	tx, err := d.beginTx(ctx)
	if err != nil {
		return SchemaNone, err
	}
	row := d.queryRowTx(tx, ctx, "SELECT schema FROM version")
	var schema SchemaVersion
	err = row.Scan(&schema)
	if err != nil {
		return SchemaNone, d.rollbackTx(tx, nil)
	}
	return schema, d.commitTx(tx)
}

func (d *databaseDriver) InsertAuthRequest(ctx context.Context, authRequest *AuthRequest) error {
	d.logger.Debug("inserting auth request", slog.String("id", authRequest.ID))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	args0 := []any{
		authRequest.ID,
		authRequest.ACR,
		authRequest.CreateTime,
		authRequest.AuthTime,
		authRequest.ClientID,
		authRequest.Nonce,
		authRequest.RedirectURI,
		authRequest.ResponseType,
		authRequest.ResponseMode,
		authRequest.State,
		authRequest.Subject,
		authRequest.Done,
	}
	err = d.execTx(tx, ctx, "INSERT INTO auth_request (id,acr,create_time,auth_time,client_id,nonce,redirect_uri,response_type,response_mode,state,subject,done) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)", args0...)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	for _, amr := range authRequest.AMR {
		err = d.execTx(tx, ctx, "INSERT INTO auth_request_amr (amr,auth_request_id) VALUES($1,$2)", amr, authRequest.ID)
		if err != nil {
			return d.rollbackTx(tx, err)
		}
	}
	for _, audience := range authRequest.Audience {
		err = d.execTx(tx, ctx, "INSERT INTO auth_request_audience (audience,auth_request_id) VALUES($1,$2)", audience, authRequest.ID)
		if err != nil {
			return d.rollbackTx(tx, err)
		}
	}
	if authRequest.CodeChallenge != nil {
		err = d.execTx(tx, ctx, "INSERT INTO auth_request_code_challenge (challenge,method,auth_request_id) VALUES($1,$2,$3)", authRequest.CodeChallenge.Challenge, authRequest.CodeChallenge.Method, authRequest.ID)
		if err != nil {
			return d.rollbackTx(tx, err)
		}
	}
	for _, scope := range authRequest.Scopes {
		err = d.execTx(tx, ctx, "INSERT INTO auth_request_scope (scope,auth_request_id) VALUES($1,$2)", scope, authRequest.ID)
		if err != nil {
			return d.rollbackTx(tx, err)
		}
	}
	return d.commitTx(tx)
}

func (d *databaseDriver) SelectAuthRequest(ctx context.Context, id string) (*AuthRequest, error) {
	d.logger.Debug("selecting auth request", slog.String("id", id))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	authRequest, err := d.selectAuthRequest(tx, ctx, id)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectAuthRequestAMRs(tx, ctx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectAuthRequestAudiences(tx, ctx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectAuthRequestCodeChallenge(tx, ctx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectAuthRequestScopes(tx, ctx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return authRequest, d.commitTx(tx)
}

func (d *databaseDriver) selectAuthRequest(tx *sql.Tx, ctx context.Context, id string) (*AuthRequest, error) {
	authRequest := &AuthRequest{
		ID:       id,
		AMR:      []string{},
		Audience: []string{},
		Scopes:   []string{},
	}
	row := d.queryRowTx(tx, ctx, "SELECT acr,create_time,auth_time,client_id,nonce,redirect_uri,response_type,response_mode,state,subject,done FROM auth_request WHERE id=$1", authRequest.ID)
	args := []any{
		&authRequest.ACR,
		&authRequest.CreateTime,
		&authRequest.AuthTime,
		&authRequest.ClientID,
		&authRequest.Nonce,
		&authRequest.RedirectURI,
		&authRequest.ResponseType,
		&authRequest.ResponseMode,
		&authRequest.State,
		&authRequest.Subject,
		&authRequest.Done,
	}
	err := row.Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w (unknown auth request: %s)", ErrObjectNotFound, authRequest.ID)
	} else if err != nil {
		return nil, fmt.Errorf("select auth request failure (cause: %w)", err)
	}
	return authRequest, nil
}

func (d *databaseDriver) selectAuthRequestAMRs(tx *sql.Tx, ctx context.Context, authRequest *AuthRequest) error {
	rows, err := d.queryTx(tx, ctx, "SELECT amr FROM auth_request_amr WHERE auth_request_id=$1", authRequest.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var amr string
		err = rows.Scan(&amr)
		if err != nil {
			return fmt.Errorf("select auth request amr failure (cause: %w)", err)
		}
		authRequest.AMR = append(authRequest.AMR, amr)
	}
	return nil
}

func (d *databaseDriver) selectAuthRequestAudiences(tx *sql.Tx, ctx context.Context, authRequest *AuthRequest) error {
	rows, err := d.queryTx(tx, ctx, "SELECT audience FROM auth_request_audience WHERE auth_request_id=$1", authRequest.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var audience string
		err = rows.Scan(&audience)
		if err != nil {
			return fmt.Errorf("select auth request audience failure (cause: %w)", err)
		}
		authRequest.Audience = append(authRequest.Audience, audience)
	}
	return nil
}

func (d *databaseDriver) selectAuthRequestCodeChallenge(tx *sql.Tx, ctx context.Context, authRequest *AuthRequest) error {
	row := d.queryRowTx(tx, ctx, "SELECT challenge,method FROM auth_request_code_challenge WHERE auth_request_id=$1", authRequest.ID)
	var challenge string
	var method oidc.CodeChallengeMethod
	err := row.Scan(&challenge, &method)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return fmt.Errorf("select auth request code challenge failure (cause: %w)", err)
	}
	authRequest.CodeChallenge = &oidc.CodeChallenge{
		Challenge: challenge,
		Method:    method,
	}
	return nil
}

func (d *databaseDriver) selectAuthRequestScopes(tx *sql.Tx, ctx context.Context, authRequest *AuthRequest) error {
	rows, err := d.queryTx(tx, ctx, "SELECT scope FROM auth_request_scope WHERE auth_request_id=$1", authRequest.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var scope string
		err = rows.Scan(&scope)
		if err != nil {
			return fmt.Errorf("select auth request scope failure (cause: %w)", err)
		}
		authRequest.Scopes = append(authRequest.Scopes, scope)
	}
	return nil
}

func (d *databaseDriver) SelectAuthRequestByCode(ctx context.Context, code string) (*AuthRequest, error) {
	d.logger.Debug("selecting auth request id by auth code", slog.String("code", code))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	// TODO: Optimize via join
	rows0, err := d.queryTx(tx, ctx, "SELECT auth_request_id FROM auth_code WHERE code=$1", code)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	defer rows0.Close()
	var id string
	if !rows0.Next() {
		return nil, d.rollbackTx(tx, fmt.Errorf("%w (unknown auth code: %s)", ErrObjectNotFound, code))
	}
	err = rows0.Scan(&id)
	if err != nil {
		return nil, d.rollbackTx(tx, fmt.Errorf("select auth code failure (cause: %w)", err))
	}
	rows0.Close()
	authRequest := &AuthRequest{
		ID:       id,
		AMR:      []string{},
		Audience: []string{},
		Scopes:   []string{},
	}
	rows, err := d.queryTx(tx, ctx, "SELECT acr,create_time,auth_time,client_id,nonce,redirect_uri,response_type,response_mode,state,subject,done FROM auth_request WHERE id=$1", authRequest.ID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, d.rollbackTx(tx, fmt.Errorf("%w (unknown auth request: %s)", ErrObjectNotFound, id))
	}
	args := []any{
		&authRequest.ACR,
		&authRequest.CreateTime,
		&authRequest.AuthTime,
		&authRequest.ClientID,
		&authRequest.Nonce,
		&authRequest.RedirectURI,
		&authRequest.ResponseType,
		&authRequest.ResponseMode,
		&authRequest.State,
		&authRequest.Subject,
		&authRequest.Done,
	}
	err = rows.Scan(args...)
	if err != nil {
		return nil, d.rollbackTx(tx, fmt.Errorf("select auth request failure (cause: %w)", err))
	}
	rows.Close()
	err = d.selectAuthRequestAMRs(tx, ctx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectAuthRequestAudiences(tx, ctx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectAuthRequestCodeChallenge(tx, ctx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.selectAuthRequestScopes(tx, ctx, authRequest)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return authRequest, d.commitTx(tx)
}

func (d *databaseDriver) AuthenticateAndTransformAuthRequestToUserSessionRequest(ctx context.Context, id string, email string, remember bool) (*UserSessionRequest, error) {
	d.logger.Debug("authenticating and transforming auth request to user session request", slog.String("id", id))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	authRequest, err := d.selectAuthRequest(tx, ctx, id)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	authRequest.AuthTime = time.Now().UnixMicro()
	authRequest.Subject = email
	authRequest.Done = true
	args0 := []any{
		authRequest.AuthTime,
		authRequest.Subject,
		authRequest.Done,
		authRequest.ID,
	}
	err = d.execTx(tx, ctx, "UPDATE auth_request SET auth_time=$1,subject=$2,done=$3 WHERE id=$4", args0...)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	userSessionRequest := NewUserSessionRequest(authRequest.State, remember)
	args1 := []any{
		userSessionRequest.ID,
		userSessionRequest.State,
		userSessionRequest.CreateTime,
		userSessionRequest.Remember,
	}
	err = d.execTx(tx, ctx, "INSERT INTO user_session_request (id,state,create_time,remember) VALUES($1,$2,$3,$4)", args1...)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return userSessionRequest, d.commitTx(tx)
}

func (d *databaseDriver) DeleteAuthRequest(ctx context.Context, id string) error {
	d.logger.Debug("deleting auth request", slog.String("id", id))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	err = d.execTx(tx, ctx, "DELETE FROM auth_code WHERE auth_request_id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, ctx, "DELETE FROM auth_request_scope WHERE auth_request_id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, ctx, "DELETE FROM auth_request_code_challenge WHERE auth_request_id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, ctx, "DELETE FROM auth_request_audience WHERE auth_request_id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, ctx, "DELETE FROM auth_request_amr WHERE auth_request_id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.execTx(tx, ctx, "DELETE FROM auth_request WHERE id=$1", id)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx)
}

func (d *databaseDriver) InsertAuthCode(ctx context.Context, code string, id string) error {
	d.logger.Debug("inserting auth code", slog.String("code", code))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	args := []any{
		code,
		id,
	}
	err = d.execTx(tx, ctx, "INSERT INTO auth_code (code,auth_request_id) VALUES($1,$2)", args...)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx)
}

func (d *databaseDriver) InsertToken(ctx context.Context, token *Token) error {
	d.logger.Debug("inserting token", slog.String("id", token.ID))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	err = d.insertToken(tx, ctx, token)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx)
}

func (d *databaseDriver) insertToken(tx *sql.Tx, ctx context.Context, token *Token) error {
	args0 := []any{
		token.ID,
		token.ApplicationID,
		token.Subject,
		token.RefreshTokenID,
		token.Expiration,
	}
	err := d.execTx(tx, ctx, "INSERT INTO token (id,application_id,subject,refresh_token_id,expiration) VALUES($1,$2,$3,$4,$5)", args0...)
	if err != nil {
		return err
	}
	for _, audience := range token.Audience {
		err = d.execTx(tx, ctx, "INSERT INTO token_audience (audience,token_id) VALUES($1,$2)", audience, token.ID)
		if err != nil {
			return err
		}
	}
	for _, scope := range token.Scopes {
		err = d.execTx(tx, ctx, "INSERT INTO token_scope (scope,token_id) VALUES($1,$2)", scope, token.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *databaseDriver) SelectToken(ctx context.Context, id string) (*Token, error) {
	d.logger.Debug("selecting token", slog.String("id", id))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	token := &Token{
		ID:       id,
		Audience: []string{},
		Scopes:   []string{},
	}
	row := d.queryRowTx(tx, ctx, "SELECT application_id,subject,refresh_token_id,expiration FROM token WHERE id=$1", token.ID)
	args0 := []any{
		&token.ApplicationID,
		&token.Subject,
		&token.RefreshTokenID,
		&token.Expiration,
	}
	err = row.Scan(args0...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, d.rollbackTx(tx, fmt.Errorf("%w (unknown token: %s)", ErrObjectNotFound, token.ID))
	} else if err != nil {
		return nil, d.rollbackTx(tx, fmt.Errorf("select token failure (cause: %w)", err))
	}
	rows1, err := d.queryTx(tx, ctx, "SELECT audience FROM token_audience WHERE token_id=$1", token.ID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	defer rows1.Close()
	for rows1.Next() {
		var audience string
		err = rows1.Scan(&audience)
		if err != nil {
			return nil, d.rollbackTx(tx, fmt.Errorf("select token audience failure (cause: %w)", err))
		}
		token.Audience = append(token.Audience, audience)
	}
	rows1.Close()
	rows2, err := d.queryTx(tx, ctx, "SELECT scope FROM token_scope WHERE token_id=$1", token.ID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var scope string
		err = rows2.Scan(&scope)
		if err != nil {
			return nil, d.rollbackTx(tx, fmt.Errorf("select token scope failure (cause: %w)", err))
		}
		token.Scopes = append(token.Scopes, scope)
	}
	rows2.Close()
	return token, d.commitTx(tx)
}

func (d *databaseDriver) deleteToken(tx *sql.Tx, ctx context.Context, id string) error {
	err := d.execTx(tx, ctx, "DELETE FROM token_scope WHERE token_id=$1", id)
	if err != nil {
		return err
	}
	err = d.execTx(tx, ctx, "DELETE FROM token_audience WHERE token_id=$1", id)
	if err != nil {
		return err
	}
	err = d.execTx(tx, ctx, "DELETE FROM token WHERE id=$1", id)
	if err != nil {
		return err
	}
	return nil
}

func (d *databaseDriver) InsertRefreshToken(ctx context.Context, refreshToken *RefreshToken, token *Token) error {
	d.logger.Debug("inserting refresh token", slog.String("id", refreshToken.ID))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return err
	}
	err = d.insertToken(tx, ctx, token)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	err = d.insertRefreshToken(tx, ctx, refreshToken)
	if err != nil {
		return d.rollbackTx(tx, err)
	}
	return d.commitTx(tx)
}

func (d *databaseDriver) insertRefreshToken(tx *sql.Tx, ctx context.Context, refreshToken *RefreshToken) error {
	args0 := []any{
		refreshToken.ID,
		refreshToken.AuthTime,
		refreshToken.UserID,
		refreshToken.ApplicationID,
		refreshToken.Expiration,
		refreshToken.AccessTokenID,
	}
	err := d.execTx(tx, ctx, "INSERT INTO refresh_token (id,auth_time,user_id,application_id,expiration,access_token_id) VALUES($1,$2,$3,$4,$5,$6)", args0...)
	if err != nil {
		return err
	}
	for _, amr := range refreshToken.AMR {
		err = d.execTx(tx, ctx, "INSERT INTO refresh_token_amr (amr,refresh_token_id) VALUES($1,$2)", amr, refreshToken.ID)
		if err != nil {
			return err
		}
	}
	for _, audience := range refreshToken.Audience {
		err = d.execTx(tx, ctx, "INSERT INTO refresh_token_audience (audience,refresh_token_id) VALUES($1,$2)", audience, refreshToken.ID)
		if err != nil {
			return err
		}
	}
	for _, scope := range refreshToken.Scopes {
		err = d.execTx(tx, ctx, "INSERT INTO refresh_token_scope (scope,refresh_token_id) VALUES($1,$2)", scope, refreshToken.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *databaseDriver) RenewRefreshToken(ctx context.Context, id string, newToken *Token) (*RefreshToken, error) {
	d.logger.Debug("renewing refresh token", slog.String("id", id))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	oldRefreshToken, err := d.selectRefreshToken(tx, ctx, id)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	newRefreshToken := NewRefreshTokenFromRefreshToken(newToken.RefreshTokenID, newToken.ID, oldRefreshToken)
	err = d.deleteRefreshToken(tx, ctx, oldRefreshToken.ID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.deleteToken(tx, ctx, oldRefreshToken.AccessTokenID)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.insertToken(tx, ctx, newToken)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	err = d.insertRefreshToken(tx, ctx, newRefreshToken)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return newRefreshToken, d.commitTx(tx)
}

func (d *databaseDriver) SelectRefreshToken(ctx context.Context, id string) (*RefreshToken, error) {
	d.logger.Debug("selecting refresh token", slog.String("id", id))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	refreshToken, err := d.selectRefreshToken(tx, ctx, id)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return refreshToken, d.commitTx(tx)
}

func (d *databaseDriver) selectRefreshToken(tx *sql.Tx, ctx context.Context, id string) (*RefreshToken, error) {
	refreshToken := &RefreshToken{
		ID:       id,
		AMR:      []string{},
		Audience: []string{},
		Scopes:   []string{},
	}
	row := d.queryRowTx(tx, ctx, "SELECT auth_time,user_id,application_id,expiration,access_token_id FROM refresh_token WHERE id=$1", refreshToken.ID)
	args := []any{
		&refreshToken.AuthTime,
		&refreshToken.UserID,
		&refreshToken.ApplicationID,
		&refreshToken.Expiration,
		&refreshToken.AccessTokenID,
	}
	err := row.Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w (unknown refresh token: %s)", ErrObjectNotFound, refreshToken.ID)
	} else if err != nil {
		return nil, fmt.Errorf("select refresh token failure (cause: %w)", err)
	}
	err = d.selectRefreshTokenAMRs(tx, ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	err = d.selectRefreshTokenAudiences(tx, ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	err = d.selectRefreshTokenScopes(tx, ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	return refreshToken, nil
}

func (d *databaseDriver) selectRefreshTokenAMRs(tx *sql.Tx, ctx context.Context, refreshToken *RefreshToken) error {
	rows, err := d.queryTx(tx, ctx, "SELECT amr FROM refresh_token_amr WHERE refresh_token_id=$1", refreshToken.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var amr string
		err = rows.Scan(&amr)
		if err != nil {
			return fmt.Errorf("select refresh token amr failure (cause: %w)", err)
		}
		refreshToken.AMR = append(refreshToken.AMR, amr)
	}
	return nil
}

func (d *databaseDriver) selectRefreshTokenAudiences(tx *sql.Tx, ctx context.Context, refreshToken *RefreshToken) error {
	rows, err := d.queryTx(tx, ctx, "SELECT audience FROM refresh_token_audience WHERE refresh_token_id=$1", refreshToken.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var audience string
		err = rows.Scan(&audience)
		if err != nil {
			return fmt.Errorf("select refresh token audience failure (cause: %w)", err)
		}
		refreshToken.Audience = append(refreshToken.Audience, audience)
	}
	return nil
}

func (d *databaseDriver) selectRefreshTokenScopes(tx *sql.Tx, ctx context.Context, refreshToken *RefreshToken) error {
	rows, err := d.queryTx(tx, ctx, "SELECT scope FROM refresh_token_scope WHERE refresh_token_id=$1", refreshToken.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var scope string
		err = rows.Scan(&scope)
		if err != nil {
			return fmt.Errorf("select refresh token scope failure (cause: %w)", err)
		}
		refreshToken.Scopes = append(refreshToken.Scopes, scope)
	}
	return nil
}

func (d *databaseDriver) deleteRefreshToken(tx *sql.Tx, ctx context.Context, id string) error {
	err := d.execTx(tx, ctx, "DELETE FROM refresh_token_scope WHERE refresh_token_id=$1", id)
	if err != nil {
		return err
	}
	err = d.execTx(tx, ctx, "DELETE FROM refresh_token_audience WHERE refresh_token_id=$1", id)
	if err != nil {
		return err
	}
	err = d.execTx(tx, ctx, "DELETE FROM refresh_token_amr WHERE refresh_token_id=$1", id)
	if err != nil {
		return err
	}
	err = d.execTx(tx, ctx, "DELETE FROM refresh_token WHERE id=$1", id)
	if err != nil {
		return err
	}
	return nil
}

func (d *databaseDriver) RotateSigningKeys(ctx context.Context, algorithm string, generateSigningKey func(string) (*SigningKey, error)) (SigningKeys, error) {
	d.logger.Debug("rotating signing keys")
	tx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMicro()
	// Delete expired keys
	err = d.execTx(tx, ctx, "DELETE FROM signing_key WHERE expiration<$1", now)
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
		return signingKeys, d.commitTx(tx)
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
	err = d.execTx(tx, ctx, "INSERT INTO signing_key (id,algorithm,private_key,public_key,passivation,expiration) VALUES($1,$2,$3,$4,$5,$6)", args...)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	// Re-select all keys
	signingKeys, err = d.selectSigningKeys(tx, ctx)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return signingKeys, d.commitTx(tx)
}

func (d *databaseDriver) selectSigningKeys(tx *sql.Tx, ctx context.Context) (SigningKeys, error) {
	rows, err := d.queryTx(tx, ctx, "SELECT id,algorithm,private_key,public_key,passivation,expiration FROM signing_key ORDER BY passivation,expiration DESC")
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
	tx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	userSessionRequest, err := d.selectUserSessionRequestByState(tx, ctx, state)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	userSession := NewUserSession(token, userSessionRequest.Remember)
	args := []any{
		userSession.ID,
		userSession.Remember,
		userSession.AccessToken,
		userSession.TokenType,
		userSession.RefreshToken,
		userSession.Expiration,
	}
	err = d.execTx(tx, ctx, "INSERT INTO user_session (id,remember,access_token,token_type,refresh_token,expiration) VALUES($1,$2,$3,$4,$5,$6)", args...)
	if err != nil {
		return nil, d.rollbackTx(tx, err)
	}
	return userSession, d.commitTx(tx)
}

func (d *databaseDriver) selectUserSessionRequestByState(tx *sql.Tx, ctx context.Context, state string) (*UserSessionRequest, error) {
	userSessionRequest := &UserSessionRequest{
		State: state,
	}
	row := d.queryRowTx(tx, ctx, "SELECT id,create_time,remember FROM user_session_request WHERE state=$1", userSessionRequest.State)
	args := []any{
		&userSessionRequest.ID,
		&userSessionRequest.CreateTime,
		&userSessionRequest.Remember,
	}
	err := row.Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w (unknown user session request state: %s)", ErrObjectNotFound, userSessionRequest.State)
	} else if err != nil {
		return nil, fmt.Errorf("select user session request failure (cause: %w)", err)
	}
	return userSessionRequest, nil
}

func (d *databaseDriver) SelectUserSession(ctx context.Context, id string) (*UserSession, error) {
	d.logger.Debug("selecting user session", slog.String("id", id))
	tx, err := d.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	userSession := &UserSession{
		ID: id,
	}
	row := d.queryRowTx(tx, ctx, "SELECT remember,access_token,token_type,refresh_token,expiration FROM user_session WHERE id=$1", userSession.ID)
	args := []any{
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
	return userSession, d.commitTx(tx)
}

func (d *databaseDriver) Close() error {
	return d.db.Close()
}

func (d *databaseDriver) beginTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transaction failure (cause: %w)", err)
	}
	return tx, nil
}

func (d *databaseDriver) rollbackTx(tx *sql.Tx, err error) error {
	rollbackErr := tx.Rollback()
	if rollbackErr != nil {
		d.logger.Warn("rollback failure", slog.Any("err", err))
	}
	return errors.Join(err, rollbackErr)
}

func (d *databaseDriver) commitTx(tx *sql.Tx) error {
	err := tx.Commit()
	if err != nil {
		return fmt.Errorf("commit failure (cause: %w)", err)
	}
	return nil
}

func (d *databaseDriver) execTx(tx *sql.Tx, ctx context.Context, query string, args ...any) error {
	d.logger.Debug("sql exec", slog.String("query", query))
	_, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("exec failure (cause: %w)", err)
	}
	return nil
}

func (d *databaseDriver) queryRowTx(tx *sql.Tx, ctx context.Context, query string, args ...any) *sql.Row {
	d.logger.Debug("sql query", slog.String("query", query))
	return tx.QueryRowContext(ctx, query, args...)
}

func (d *databaseDriver) queryTx(tx *sql.Tx, ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	d.logger.Debug("sql query", slog.String("query", query))
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query failure (cause: %w)", err)
	}
	return rows, nil
}

func (d *databaseDriver) runScriptTx(tx *sql.Tx, ctx context.Context, script []byte) error {
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
		_, err = tx.ExecContext(ctx, statement)
		if err != nil {
			return fmt.Errorf("script exec error at %d (cause: %w)", reader.LineNo(), err)
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
		line, prefix, err := r.reader.ReadLine()
		if errors.Is(err, io.EOF) {
			if statement != "" {
				return statement, fmt.Errorf("unclosed statement at %d", r.lineNo)
			}
			return statement, err
		} else if err != nil {
			return statement, fmt.Errorf("failed to read script (cause: %w)", err)
		}
		r.lineNo++
		if prefix {
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
