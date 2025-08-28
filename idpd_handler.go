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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/tdrn-org/idpd/internal/server"
	"github.com/tdrn-org/idpd/internal/server/database"
	"github.com/tdrn-org/idpd/internal/server/geoip"
	"github.com/tdrn-org/idpd/internal/trace"
	"github.com/tdrn-org/idpd/oauth2client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type UserInfo struct {
	Name                 string              `json:"name"`
	Subject              string              `json:"subject"`
	Email                string              `json:"email"`
	EmailVerification    UserVerificationLog `json:"email_verification"`
	TOTPVerification     UserVerificationLog `json:"totp_verification"`
	PasskeyVerification  UserVerificationLog `json:"passkey_verification"`
	WebAuthnVerification UserVerificationLog `json:"webauthn_verification"`
}

type UserVerificationLog struct {
	Registration time.Time `json:"registration,omitzero"`
	LastUsed     time.Time `json:"last_used,omitzero"`
	Host         string    `json:"host"`
	Country      string    `json:"country,omitempty"`
	CountryCode  string    `json:"country_code,omitempty"`
	City         string    `json:"city,omitempty"`
	Lat          float64   `json:"lat"`
	Lon          float64   `json:"lon"`
}

func (l *UserVerificationLog) update(log *database.UserVerificationLog) {
	l.Registration = time.UnixMicro(log.FirstUsed)
	l.LastUsed = time.UnixMicro(log.LastUsed)
	l.Host = log.Host
	l.Country = log.Country
	l.CountryCode = log.CountryCode
	l.City = log.City
	l.Lat = log.Lat
	l.Lon = log.Lon
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := s.tracer.Start(r.Context(), "handleSession")
	defer span.End()
	traceR := r.WithContext(traceCtx)

	_, client, err := s.userSessionClient(traceR)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	oidcUserInfo, err := s.authFLow.GetUserInfo(client, traceCtx)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to get user info", slog.Any("err", err))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	name := oidcUserInfo.Name
	if name == "" {
		name = oidcUserInfo.Subject
	}
	userInfo := &UserInfo{
		Name:    name,
		Subject: oidcUserInfo.Subject,
		Email:   oidcUserInfo.Email,
		EmailVerification: UserVerificationLog{
			LastUsed: time.Now(),
			Host:     r.RemoteAddr,
		},
	}
	logs, err := s.database.SelectUserVerificationLogs(traceCtx, userInfo.Subject)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to read user verification logs", slog.String("subject", userInfo.Subject), slog.Any("err", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	for _, log := range logs {
		switch server.VerifyMethod(log.Method) {
		case server.VerifyMethodEmail:
			userInfo.EmailVerification.update(log)
		case server.VerifyMethodTOTP:
			userInfo.TOTPVerification.update(log)
		case server.VerifyMethodPasskey:
			userInfo.PasskeyVerification.update(log)
		case server.VerifyMethodWebAuthn:
			userInfo.WebAuthnVerification.update(log)
		default:
			slog.Warn("unexpected verification log", slog.String("method", log.Method))
		}
	}
	err = json.NewEncoder(w).Encode(userInfo)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to encode session response", slog.Any("err", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleSessionDetails(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := s.tracer.Start(r.Context(), "handleSessionDetails")
	defer span.End()
	traceR := r.WithContext(traceCtx)

	_, client, err := s.userSessionClient(traceR)
	if err != nil {
		trace.RecordError(span, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	oidcUserInfo, err := s.authFLow.GetUserInfo(client, traceCtx)
	if err != nil {
		trace.RecordError(span, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	err = encoder.Encode(oidcUserInfo)
	if err != nil {
		trace.RecordError(span, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleSessionAuthenticate(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := s.tracer.Start(r.Context(), "handleSessionAuthenticate")
	defer span.End()
	traceR := r.WithContext(traceCtx)

	id, subject, password, verification, remember, err := s.parseAuthenticateForm(traceR)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to process authenticate session request", slog.Any("err", err))
		s.redirectAlert(w, traceR, AlertLoginFailure)
		return
	}
	verifyHandler := s.getVerifyHandler(verification)
	verifyHandlerCtx := s.verifyHandlerContext(traceCtx, verifyHandler, r)
	redirectURL, err := s.oauth2Provider.Authenticate(verifyHandlerCtx, id, subject, password, verifyHandler, remember)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to authenticate OAuth2 session", slog.String("id", id), slog.String("subject", subject), slog.Any("err", err))
		s.redirectAlert(w, traceR, AlertLoginFailure)
		return
	}
	http.Redirect(w, traceR, redirectURL, http.StatusFound)
}

func (s *Server) getVerifyHandler(verification string) server.VerifyHandler {
	switch server.VerifyMethod(verification) {
	case server.VerifyMethodEmail:
		return server.NewEmailVerifyHandler(s.mailer, s.database, s.userStore)
	case server.VerifyMethodTOTP:
		return server.NewTOTPVerifyHandler(s.totpProvider, s.database, false)
	case server.VerifyMethodPasskey:
		return server.NoneVerifyHandler()
	case server.VerifyMethodWebAuthn:
		return server.NoneVerifyHandler()
	default:
		return server.NoneVerifyHandler()
	}
}

func (s *Server) parseAuthenticateForm(r *http.Request) (string, string, string, string, bool, error) {
	if r.Method != http.MethodPost {
		return "", "", "", "", false, fmt.Errorf("invalid authenticate session request")
	}
	err := r.ParseForm()
	if err != nil {
		return "", "", "", "", false, fmt.Errorf("failed to parse authenticate session request")
	}
	id := r.PostFormValue("id")
	subject := r.PostFormValue("subject")
	password := r.PostFormValue("password")
	verification := r.PostFormValue("verification")
	if id == "" || subject == "" || password == "" || verification == "" {
		return "", "", "", "", false, fmt.Errorf("incomplete authenticate session request (id='%s', subject='%s', verification='%s')", id, subject, verification)
	}
	remember, _ := strconv.ParseBool(r.PostFormValue("remember"))
	return id, subject, password, verification, remember, nil
}

func (s *Server) handleSessionVerify(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := s.tracer.Start(r.Context(), "handleSessionVerify")
	defer span.End()
	traceR := r.WithContext(traceCtx)

	id, subject, verification, response, err := s.parseVerifyForm(traceR)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to process verify session request", slog.Any("err", err))
		s.redirectAlert(w, traceR, AlertLoginFailure)
		return
	}
	verifyHandler := s.getVerifyHandler(verification)
	verifyHandlerCtx := s.verifyHandlerContext(traceCtx, verifyHandler, r)
	redirectURL, err := s.oauth2Provider.Verify(verifyHandlerCtx, id, subject, verifyHandler, response)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to verify OAuth2 session", slog.String("id", id), slog.String("subject", subject), slog.Any("err", err))
		s.redirectAlert(w, r, AlertLoginFailure)
		return
	}
	http.Redirect(w, traceR, redirectURL, http.StatusFound)
}

func (s *Server) parseVerifyForm(r *http.Request) (string, string, string, string, error) {
	if r.Method != http.MethodPost {
		return "", "", "", "", fmt.Errorf("invalid verify session request")
	}
	err := r.ParseForm()
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse verify session request")
	}
	id := r.PostFormValue("id")
	subject := r.PostFormValue("subject")
	verification := r.PostFormValue("verification")
	response := r.PostFormValue("response")
	if id == "" || subject == "" || verification == "" || response == "" {
		return "", "", "", "", fmt.Errorf("incomplete verify session request (id='%s', subject='%s', verification='%s')", id, subject, verification)
	}
	return id, subject, verification, response, nil
}

func (s *Server) handleSessionTerminate(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := s.tracer.Start(r.Context(), "handleSessionTerminate")
	defer span.End()
	traceR := r.WithContext(traceCtx)

	session, client, err := s.userSessionClient(traceR)
	if err == nil {
		session.Invalidate()
		err = s.database.UpdateUserSession(traceCtx, session)
		if err != nil {
			slog.Warn("failed to invalidate session", slog.String("id", session.ID), slog.Any("err", err))
		}
	}
	alert := AlertNone
	if err == nil {
		endSessionResponse, err := client.Get(s.authFLow.GetEndSessionEndpoint())
		if err != nil || endSessionResponse.StatusCode != http.StatusOK {
			alert = AlertLogoffFailure
		}
	}
	s.sessionCookie.Delete(w)
	if alert != AlertNone {
		s.redirectAlert(w, r, alert)
	}
	http.Redirect(w, r, s.oauth2IssuerURL.String(), http.StatusFound)
}

type UserTOTPRegistrationRequest struct {
	QRCode string `json:"qr_code"`
	OTPUrl string `json:"otp_url"`
}

func (s *Server) handleSessionTOTPRegister(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := s.tracer.Start(r.Context(), "handleSessionTerminate")
	defer span.End()
	traceR := r.WithContext(traceCtx)

	session, err := s.userSession(traceR)
	if err != nil {
		trace.RecordError(span, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	secret, qrCode, otpURL, err := s.totpProvider.GenerateRegistrationRequest(session.Subject, 256, 256)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to generate TOTP registration request", slog.String("subject", session.Subject), slog.Any("err", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	verifyHandler := server.NewTOTPVerifyHandler(s.totpProvider, s.database, true)
	_, err = s.database.GenerateUserTOTPRegistrationRequest(traceCtx, session.Subject, secret, verifyHandler.GenerateChallenge)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to generate user TOTP registration request", slog.String("subject", session.Subject), slog.Any("err", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	registrationInfo := &UserTOTPRegistrationRequest{
		QRCode: qrCode,
		OTPUrl: otpURL,
	}
	err = json.NewEncoder(w).Encode(registrationInfo)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to encode session TOTP register response", slog.Any("err", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleSessionTOTPVerify(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := s.tracer.Start(r.Context(), "handleSessionTerminate")
	defer span.End()
	traceR := r.WithContext(traceCtx)

	session, err := s.userSession(traceR)
	if err != nil {
		trace.RecordError(span, err)
		s.redirectAlert(w, r, AlertLoginFailure)
		return
	}
	response, err := s.parseVerifyTOTPForm(traceR)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to process verify TOTP request", slog.Any("err", err))
		s.redirectAlert(w, r, AlertLoginFailure)
		return
	}
	verifyHandler := server.NewTOTPVerifyHandler(s.totpProvider, s.database, true)
	verifyHandlerCtx := s.verifyHandlerContext(traceCtx, verifyHandler, r)
	registration, err := s.database.VerifyAndTransformUserTOTPRegistrationRequestToRegistration(verifyHandlerCtx, session.Subject, verifyHandler.VerifyResponse, response)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to verify/transform user TOTP registration", slog.String("subject", session.Subject), slog.Any("err", err))
		s.redirectAlert(w, r, AlertVerifyFailure)
	}
	if registration == nil {
		// TODO: Support retry?
		s.redirectAlert(w, r, AlertVerifyFailure)
	}
	http.Redirect(w, r, s.oauth2IssuerURL.String(), http.StatusFound)
}

func (s *Server) parseVerifyTOTPForm(r *http.Request) (string, error) {
	if r.Method != http.MethodPost {
		return "", fmt.Errorf("invalid verify TOTP request")
	}
	err := r.ParseForm()
	if err != nil {
		return "", fmt.Errorf("failed to parse verify TOTP request")
	}
	response := r.PostFormValue("response")
	if response == "" {
		return "", fmt.Errorf("incomplete verify TOTP request")
	}
	return response, nil
}

func (s *Server) tokenExchange(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, flow *oauth2client.AuthorizationCodeFlow[*oidc.IDTokenClaims]) {
	traceCtx, span := s.tracer.Start(r.Context(), "handleSessionTerminate")
	defer span.End()

	userSession, remember, err := s.database.TransformAndDeleteUserSessionRequest(traceCtx, state, tokens.Token)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to transform user session request", slog.Any("err", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if userSession == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	err = s.sessionCookie.Set(w, userSession.ID, remember)
	if err != nil {
		trace.RecordError(span, err)
		slog.Warn("failed to set session cookie", slog.Any("err", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.oauth2IssuerURL.String(), http.StatusFound)
}

func (s *Server) userSession(r *http.Request) (*database.UserSession, error) {
	sessionID, exists := s.sessionCookie.Get(r)
	if !exists {
		return nil, oauth2client.ErrNotAuthenticated
	}
	session, err := s.database.SelectUserSession(r.Context(), sessionID)
	if err != nil {
		slog.Warn("failed to lookup user session", slog.String("id", sessionID), slog.Any("err", err))
		return nil, oauth2client.ErrNotAuthenticated
	}
	if session == nil {
		return nil, oauth2client.ErrNotAuthenticated
	}
	return session, nil
}

func (s *Server) userSessionClient(r *http.Request) (*database.UserSession, *http.Client, error) {
	session, err := s.userSession(r)
	if err != nil {
		return nil, nil, err
	}
	client, err := s.authFLow.Client(r.Context(), session.OAuth2Token())
	if err != nil {
		return nil, nil, err
	}
	return session, client, nil
}

func (s *Server) verifyHandlerContext(ctx context.Context, verifyHandler server.VerifyHandler, r *http.Request) context.Context {
	remoteIP := trace.GetHttpRequestRemoteIP(r)
	remoteLocation, err := s.locationService.Lookup(remoteIP)
	if err != nil {
		slog.Error("failed to lookup location info", slog.String("remoteIP", remoteIP), slog.Any("err", err))
		remoteLocation = &geoip.Location{
			Host: remoteIP,
		}
	}
	return server.VerifyHandlerContext(ctx, verifyHandler, remoteLocation)
}

type Alert string

const (
	AlertNone          Alert = ""
	AlertServerFailure Alert = "server_failure"
	AlertLoginFailure  Alert = "login_failure"
	AlertLogoffFailure Alert = "logoff_failure"
	AlertVerifyFailure Alert = "verify_failure"
)

func (s *Server) redirectAlert(w http.ResponseWriter, r *http.Request, alert Alert) {
	redirectURL := *s.oauth2IssuerURL
	query := redirectURL.Query()
	query.Add("alert", string(alert))
	redirectURL.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
