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

// Package httpserver provides http server functionality for this
// library in a pluggable manner.
package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/cors"
	"github.com/tdrn-org/go-tlsconf/tlsserver"
	"github.com/tdrn-org/idpd/internal/trace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// The Handler interface provides a generic way to mount any
// kind of service to an http server.
type Handler interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler http.HandlerFunc)
}

const serverFailureMessage = "http server failure"

// Instance provides a http server based on the standard [http.Server].
type Instance struct {
	// Addr defines the TCP address to listen on (see [net.Listen]).
	Addr string
	// AccessLog controls whether access logging is enabled or not.
	AccessLog bool
	// AllowedOrigins defines the allowed origins for cross-origin
	// requests (CORS).
	AllowedOrigins []string
	listener       net.Listener
	listenerAddr   string
	mux            *http.ServeMux
	baseURL        *url.URL
	logger         *slog.Logger
	tracer         oteltrace.Tracer
	httpServer     *http.Server
	stoppedWG      sync.WaitGroup
}

// Listen invokes [net.Listen] to establish the http servers [net.Listener].
//
// After a successfull Listen call, [ListenerAddr] can be used to retrieve
// the actual listen address.
func (s *Instance) Listen() error {
	if s.listener != nil {
		return nil
	}
	serverHost, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return fmt.Errorf("failed to decode server address %s (cause: %w)", s.Addr, err)
	}
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on address %s (cause: %w)", s.Addr, err)
	}
	listenerAddr := listener.Addr().String()
	_, listenerPort, err := net.SplitHostPort(listenerAddr)
	if err != nil {
		return fmt.Errorf("failed to decode listener address %s (cause: %w)", listenerAddr, err)
	}
	s.listener = listener
	s.listenerAddr = net.JoinHostPort(serverHost, listenerPort)
	return nil
}

// MustListen estblishes the http server's [net.Listener] like [Listen], but panics
// in case of an error.
func (s *Instance) MustListen() *Instance {
	err := s.Listen()
	if err != nil {
		slog.Error(serverFailureMessage, slog.String("server", s.Addr), slog.Any("err", err))
		panic(err)
	}
	return s
}

// ListenerAddr returns the listener address of the http server.
//
// [Listen] or [MustListen] must be invoked first, to establish the http server's [net.Listener].
// If this is not the case, "" is returned.
//
// If the Instance's Addr attribute defines an explicit port, the returned address will be equal
// to the Addr attribute. Otherwise the returned address contains the choosen port.
func (s *Instance) ListenerAddr() string {
	return s.listenerAddr
}

// Handle
func (s *Instance) Handle(pattern string, handler http.Handler) {
	if s.mux == nil {
		s.mux = http.NewServeMux()
	}
	slog.Debug("http server pattern", slog.String("server", s.Addr), slog.String("pattern", pattern))
	s.mux.Handle(pattern, handler)
}

func (s *Instance) HandleFunc(pattern string, handler http.HandlerFunc) {
	if s.mux == nil {
		s.mux = http.NewServeMux()
	}
	slog.Debug("http server pattern", slog.String("server", s.Addr), slog.String("pattern", pattern))
	s.mux.HandleFunc(pattern, handler)
}

func (s *Instance) BaseURL() *url.URL {
	return s.baseURL
}

func (s *Instance) prepareServe(schema string) (*cors.Cors, error) {
	err := s.Listen()
	if err != nil {
		return nil, err
	}
	if s.mux == nil {
		s.mux = http.NewServeMux()
	}
	baseURL, err := url.Parse(schema + "://" + s.listenerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL (cause: %w)", err)
	}
	s.baseURL = baseURL
	s.logger = slog.With(slog.Any("baseURL", s.baseURL))
	s.tracer = otel.Tracer(reflect.TypeFor[Instance]().PkgPath())
	corsOptions := cors.Options{
		AllowedOrigins: s.AllowedOrigins,
	}
	cors := cors.New(corsOptions)
	return cors, nil
}

func (s *Instance) runServe(serve func() error) {
	s.stoppedWG.Go(func() {
		s.logger.Info("http server started")
		err := serve()
		if !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error(serverFailureMessage, slog.Any("err", err))
		} else {
			s.logger.Info("http server stopped")
		}
	})
}

func (s *Instance) Serve() error {
	cors, err := s.prepareServe("http")
	if err != nil {
		return err
	}
	s.httpServer = &http.Server{
		Addr:    s.Addr,
		Handler: cors.Handler(s),
	}
	s.runServe(func() error {
		return s.httpServer.Serve(s.listener)
	})
	return nil
}

func (s *Instance) ServeTLS(certFile string, keyFile string) error {
	cors, err := s.prepareServe("https")
	if err != nil {
		return err
	}
	var certificates []tls.Certificate
	if certFile == "" && keyFile == "" {
		s.logger.Info("using ephemeral certificate")
		certificate, err := tlsserver.GenerateEphemeralCertificate(s.listenerAddr, tlsserver.CertificateAlgorithmDefault)
		if err != nil {
			return err
		}
		certificates = append(certificates, *certificate)
	}
	s.httpServer = &http.Server{
		Addr:    s.Addr,
		Handler: cors.Handler(s),
		TLSConfig: &tls.Config{
			Certificates: certificates,
		},
	}
	s.runServe(func() error {
		return s.httpServer.ServeTLS(s.listener, certFile, keyFile)
	})
	return nil
}

func (s *Instance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := trace.ServerStart(s.tracer, r.Context(), "ServeHTTP", attribute.String("path", r.URL.Path))
	defer span.End()

	remoteIP, _, remoteIPR := s.remoteIPContextAndRequest(traceCtx, r)
	wrappedW := &wrappedResponseWriter{wrapped: w, statusCode: http.StatusOK}

	if !s.AccessLog {
		s.mux.ServeHTTP(wrappedW, remoteIPR)
	} else {
		log := &logBuilder{}
		log.appendHost(remoteIP)
		log.appendTime()
		log.appendRequest(r.Method, r.URL.Path, r.Proto)
		s.mux.ServeHTTP(wrappedW, remoteIPR)
		log.appendStatus(wrappedW.statusCode, wrappedW.written)
		s.logger.Info(log.String())
	}
	span.SetAttributes(attribute.Int("http.status_code", wrappedW.statusCode))
}

type remoteIPKeyType string

const remoteIPKey remoteIPKeyType = "remoteIP"

func (s *Instance) remoteIPContextAndRequest(ctx context.Context, r *http.Request) (string, context.Context, *http.Request) {
	remoteIP := trace.GetHttpRequestRemoteIP(r)
	remoteIPCtx := context.WithValue(ctx, remoteIPKey, remoteIP)
	remoteIPR := r.WithContext(remoteIPCtx)
	return remoteIP, remoteIPCtx, remoteIPR
}

func RemoteIPContextValue(r *http.Request) string {
	return r.Context().Value(remoteIPKey).(string)
}

func (s *Instance) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Instance) Close() error {
	return s.httpServer.Close()
}

func (s *Instance) WaitStopped() {
	s.stoppedWG.Wait()
}

type wrappedResponseWriter struct {
	wrapped    http.ResponseWriter
	written    int
	statusCode int
}

func (w *wrappedResponseWriter) Header() http.Header {
	return w.wrapped.Header()
}

func (w *wrappedResponseWriter) Write(b []byte) (int, error) {
	written, err := w.wrapped.Write(b)
	w.written += written
	return written, err
}

func (w *wrappedResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.wrapped.WriteHeader(statusCode)
}

type logBuilder struct {
	strings.Builder
}

func (b *logBuilder) appendHost(remoteIP string) {
	if remoteIP != "" {
		b.WriteString(remoteIP)
	} else {
		b.WriteRune('-')
	}
	b.WriteString(" - -")
}

func (b *logBuilder) appendTime() {
	b.WriteString(time.Now().Format(" [02/Jan/2006:15:04:05 -0700]"))
}

func (b *logBuilder) appendRequest(method string, path string, proto string) {
	b.WriteString(" \"")
	b.WriteString(method)
	b.WriteRune(' ')
	b.WriteString(path)
	b.WriteRune(' ')
	b.WriteString(proto)
	b.WriteRune('"')
}

func (b *logBuilder) appendStatus(statusCode int, written int) {
	b.WriteRune(' ')
	b.WriteString(strconv.Itoa(statusCode))
	b.WriteRune(' ')
	b.WriteString(strconv.Itoa(written))
}
