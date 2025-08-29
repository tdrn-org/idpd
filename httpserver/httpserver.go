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
	oteltrace "go.opentelemetry.io/otel/trace"
)

type Handler interface {
	HandleFunc(pattern string, handler http.HandlerFunc)
}

const serverFailureMessage = "http server failure"

type Instance struct {
	Addr            string
	AccessLog       bool
	AllowOriginFunc func(*http.Request, string) (bool, []string)
	AllowedMethods  []string
	listener        net.Listener
	listenerAddr    string
	mux             *http.ServeMux
	baseURL         *url.URL
	logger          *slog.Logger
	tracer          oteltrace.Tracer
	httpServer      *http.Server
	stoppedWG       sync.WaitGroup
}

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

func (s *Instance) MustListen() *Instance {
	err := s.Listen()
	if err != nil {
		slog.Error(serverFailureMessage, slog.String("server", s.Addr), slog.Any("err", err))
		panic(err)
	}
	return s
}

func (s *Instance) ListenerAddr() string {
	return s.listenerAddr
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
		AllowOriginVaryRequestFunc: s.AllowOriginFunc,
		AllowedMethods:             s.AllowedMethods,
	}
	cors := cors.New(corsOptions)
	return cors, nil
}

func (s *Instance) runServe(serve func() error) {
	s.stoppedWG.Add(1)
	go func() {
		defer s.stoppedWG.Done()
		s.logger.Info("http server started")
		err := serve()
		if !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error(serverFailureMessage, slog.Any("err", err))
		} else {
			s.logger.Info("http server stopped")
		}
	}()
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
	traceCtx, span := s.tracer.Start(r.Context(), r.URL.Path)
	defer span.End()
	traceR := r.WithContext(traceCtx)

	if !s.AccessLog {
		s.mux.ServeHTTP(w, traceR)
	} else {
		log := &logBuilder{}
		remoteIP := trace.GetHttpRequestRemoteIP(traceR)
		log.appendHost(remoteIP)
		log.appendTime()
		log.appendRequest(r.Method, r.URL.Path, r.Proto)
		wrappedW := &wrappedResponseWriter{wrapped: w, statusCode: http.StatusOK}
		s.mux.ServeHTTP(wrappedW, traceR)
		log.appendStatus(wrappedW.statusCode, wrappedW.written)
		s.logger.Info(log.String())
	}
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
