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
	"context"
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/httpserver"
)

const httpServerAddr string = "localhost:"
const httpServerShutdownPath string = "/shutdown"

func TestHttpServerServe(t *testing.T) {
	server := &httpserver.Instance{Addr: httpServerAddr}
	server.HandleFunc(httpServerShutdownPath, func(w http.ResponseWriter, _ *http.Request) {
		go func() {
			err := server.Shutdown(context.Background())
			require.NoError(t, err)
		}()
		w.WriteHeader(http.StatusOK)
	})
	err := server.Serve()
	require.NoError(t, err)
	client := &http.Client{}
	rsp, err := client.Get(server.BaseURI().JoinPath(httpServerShutdownPath).String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	server.WaitStopped()
}

func TestHttpServerServeTLS(t *testing.T) {
	server := &httpserver.Instance{Addr: httpServerAddr}
	server.HandleFunc(httpServerShutdownPath, func(w http.ResponseWriter, _ *http.Request) {
		go func() {
			err := server.Shutdown(context.Background())
			require.NoError(t, err)
		}()
		w.WriteHeader(http.StatusOK)
	})
	err := server.ServeTLS("", "")
	require.NoError(t, err)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	rsp, err := client.Get(server.BaseURI().JoinPath(httpServerShutdownPath).String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	server.WaitStopped()
}
