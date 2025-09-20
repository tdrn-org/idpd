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

package httpserver_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-tlsconf"
	"github.com/tdrn-org/go-tlsconf/tlsclient"
	"github.com/tdrn-org/idpd/httpserver"
)

func TestServe(t *testing.T) {
	server := newServer()
	err := server.Serve()
	require.NoError(t, err)
	client := &http.Client{}
	pingServer(t, server, client)
	server.Shutdown(t.Context())
}

func TestServeTLS(t *testing.T) {
	server := newServer()
	err := server.ServeTLS("", "")
	require.NoError(t, err)

	tlsclient.SetOptions(tlsconf.EnableInsecureSkipVerify())

	client := tlsclient.ApplyConfig(&http.Client{})
	pingServer(t, server, client)
	server.Shutdown(t.Context())
}

func TestPolicy(t *testing.T) {
	server := newServer()
	allowedNetworks, err := httpserver.ParseNetworks("127.0.0.1/32", "::1/128")
	require.NoError(t, err)
	allowedPolicy := httpserver.AllowNetworks(allowedNetworks)
	server.Handle("/allowed", httpserver.AccessPolicyHandler(http.HandlerFunc(echoHandler), allowedPolicy))
	forbiddenNetworks, err := httpserver.ParseNetworks("192.168.1.0/24", "fd::0/64")
	require.NoError(t, err)
	forbiddenPolicy := httpserver.AllowNetworks(forbiddenNetworks)
	server.Handle("/forbidden", httpserver.AccessPolicyHandler(http.HandlerFunc(echoHandler), forbiddenPolicy))
	err = server.Serve()
	require.NoError(t, err)
	client := &http.Client{}
	require.Equal(t, http.StatusOK, getServer(t, server, client, "/allowed"))
	require.Equal(t, http.StatusForbidden, getServer(t, server, client, "/forbidden"))
	server.Shutdown(t.Context())
}

func echoHandler(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("ok"))
}

func newServer() *httpserver.Instance {
	server := &httpserver.Instance{
		Addr:           "localhost:",
		AccessLog:      true,
		AllowedOrigins: []string{"localhost"},
	}
	server.HandleFunc("/ping", echoHandler)
	return server
}

func pingServer(t *testing.T, server *httpserver.Instance, client *http.Client) {
	rsp, err := client.Get(server.BaseURL().JoinPath("/ping").String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	defer rsp.Body.Close()
	responseBody, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, "ok", string(responseBody))
}

func getServer(t *testing.T, server *httpserver.Instance, client *http.Client, path string) int {
	rsp, err := client.Get(server.BaseURL().JoinPath(path).String())
	require.NoError(t, err)
	return rsp.StatusCode
}
