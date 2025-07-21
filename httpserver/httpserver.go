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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Handler interface {
	HandleFunc(pattern string, handler http.HandlerFunc)
}

const serverFailureMessage = "http server failure"

type Instance struct {
	Addr         string
	AccessLog    bool
	listener     net.Listener
	listenerAddr string
	mux          *http.ServeMux
	baseURL      *url.URL
	logger       *slog.Logger
	httpServer   *http.Server
	stoppedWG    sync.WaitGroup
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

func (s *Instance) Serve() error {
	err := s.Listen()
	if err != nil {
		return err
	}
	if s.mux == nil {
		s.mux = http.NewServeMux()
	}
	baseURL, err := url.Parse("http://" + s.listenerAddr)
	if err != nil {
		return fmt.Errorf("failed to parse base URL (cause: %w)", err)
	}
	s.baseURL = baseURL
	s.logger = slog.With(slog.Any("baseURL", s.baseURL))
	s.httpServer = &http.Server{
		Addr:    s.Addr,
		Handler: s,
	}
	s.stoppedWG.Add(1)
	go func() {
		defer s.stoppedWG.Done()
		s.logger.Info("http server started")
		err := s.httpServer.Serve(s.listener)
		if !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error(serverFailureMessage, slog.Any("err", err))
		} else {
			s.logger.Info("http server stopped")
		}
	}()
	return nil
}

func (s *Instance) ServeTLS(certFile string, keyFile string) error {
	err := s.Listen()
	if err != nil {
		return err
	}
	if s.mux == nil {
		s.mux = http.NewServeMux()
	}
	baseURL, err := url.Parse("https://" + s.listenerAddr)
	if err != nil {
		return fmt.Errorf("failed to parse base URL (cause: %w)", err)
	}
	s.baseURL = baseURL
	s.logger = slog.With(slog.Any("baseURL", s.baseURL))
	var certificates []tls.Certificate
	if certFile == "" && keyFile == "" {
		s.logger.Info("using ephemeral certificate")
		certificate, err := httpEphemeralCertificateForAddress(s.listenerAddr)
		if err != nil {
			return err
		}
		certificates = append(certificates, *certificate)
	}
	s.httpServer = &http.Server{
		Addr:    s.Addr,
		Handler: s,
		TLSConfig: &tls.Config{
			Certificates: certificates,
		},
	}
	s.stoppedWG.Add(1)
	go func() {
		defer s.stoppedWG.Done()
		s.logger.Info("http server started")
		err := s.httpServer.ServeTLS(s.listener, certFile, keyFile)
		if !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error(serverFailureMessage, slog.Any("err", err))
		} else {
			s.logger.Info("http server stopped")
		}
	}()
	return nil
}

func (s *Instance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("http server request", slog.String(r.Method, r.RequestURI))
	if !s.AccessLog {
		s.mux.ServeHTTP(w, r)
	} else {
		log := &logBuilder{}
		log.appendHost(r.RemoteAddr)
		log.appendTime()
		log.appendRequest(r.Method, r.URL.EscapedPath(), r.Proto)
		wrappedW := &wrappedResponseWriter{wrapped: w, statusCode: http.StatusOK}
		s.mux.ServeHTTP(wrappedW, r)
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

func (b *logBuilder) appendHost(remoteAddr string) {
	if remoteAddr != "" {
		b.WriteString(remoteAddr)
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

func httpEphemeralCertificateForAddress(address string) (*tls.Certificate, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q (cause: %w)", address, err)
	}
	publicKey, privateKey, keyBlock, err := httpEphemeralCertificateKey()
	if err != nil {
		return nil, err
	}
	x509Block, err := httpEphemeralCertificateX509(host, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(x509Block), pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate (cause: %w)", err)
	}
	return &certificate, nil
}

func httpEphemeralCertificateKey() (crypto.PublicKey, crypto.PrivateKey, *pem.Block, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate key (cause: %w)", err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode key (cause: %w)", err)
	}
	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encodedKey,
	}
	return &key.PublicKey, key, keyBlock, nil
}

func httpEphemeralCertificateX509(host string, publicKey crypto.PublicKey, privateKey crypto.PrivateKey) (*pem.Block, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, 1),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}
	x509Bytes, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate (cause: %w)", err)
	}
	x509Block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x509Bytes,
	}
	return x509Block, nil
}
