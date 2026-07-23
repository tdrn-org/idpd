/*
 * Copyright 2025-2026 Holger de Carne
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

package oauth2client_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd"
	"github.com/tdrn-org/idpd/config"
	"github.com/tdrn-org/idpd/oauth2client"
	"golang.org/x/oauth2"
)

func TestOIDCCodeFlow(t *testing.T) {
	server := runTestServer(t, "testdata/idpd.toml")
	defer server.Close()

	var flow *oauth2client.OIDCCodeFlow
	var flowSessionData *oauth2client.NonceSessionData
	redirectURL := server.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		authResult, err := flow.Callback(r.Context(), r, flowSessionData)
		require.NoError(t, err)
		fmt.Println(authResult)
	})
	clientConfig := oauth2client.NewOIDCCodeFlowClientConfig("testclient", "testsecret", false, redirectURL)
	server.OAuth2().AddClient(clientConfig)
	oauth2Config := &oauth2.Config{
		ClientID:     clientConfig.ID,
		ClientSecret: clientConfig.Secret,
		Endpoint:     *server.OAuth2().Endpoint(),
		RedirectURL:  clientConfig.RedirectURLStrings()[0],
		Scopes:       clientConfig.AllowedScopes,
	}
	flow = oauth2client.NewOIDCCodeFLow(oauth2Config)
	authURL, sessionData, err := flow.Init(t.Context())
	require.NoError(t, err)
	flowSessionData = sessionData
	rsp, err := http.Get(authURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	server.Shutdown(t.Context())
}

func runTestServer(t *testing.T, path string) *idpd.Server {
	cfg, err := config.Load(path, true)
	require.NoError(t, err)
	server, err := idpd.StartServer(t.Context(), cfg)
	require.NoError(t, err)
	go func() {
		err := server.Run(t.Context())
		require.NoError(t, err)
	}()
	return server
}
