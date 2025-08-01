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

package oauth2client_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-log"
	"github.com/tdrn-org/idpd"
	"github.com/tdrn-org/idpd/httpserver"
	"github.com/tdrn-org/idpd/oauth2client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestAuthorizationCodeFlow(t *testing.T) {
	idpdServer := idpd.MustStart(t.Context(), "testdata/idpd.toml")
	callbackServer := (&httpserver.Instance{Addr: "localhost:", AccessLog: true}).MustListen()
	clientBaseURL := "http://" + callbackServer.ListenerAddr()
	client := &idpd.OAuth2Client{
		ID:           "authorizationCodeFlowClient",
		Secret:       "secret",
		RedirectURLs: []string{clientBaseURL + "/authorized"},
	}
	idpdServer.AddOAuth2Client(client)
	config := &oauth2client.AuthorizationCodeFlowConfig[*oidc.IDTokenClaims]{
		Issuer:       idpdServer.OAuth2IssuerURL().String(),
		ClientId:     client.ID,
		ClientSecret: client.Secret,
		BaseURL:      clientBaseURL,
		Scopes:       []string{"openid", "profile", "email", "groups"},
		EnablePKCE:   true,
	}
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	flowClient := &http.Client{
		Jar: jar,
	}
	var httpClient *http.Client
	flow, err := config.NewFlow(flowClient, context.Background(), func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, flow *oauth2client.AuthorizationCodeFlow[*oidc.IDTokenClaims]) {
		httpClient, _ = flow.Client(r.Context(), tokens.Token)
		http.Redirect(w, r, clientBaseURL, http.StatusFound)
	})
	require.NoError(t, err)
	flow.Mount(callbackServer)
	callbackServer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	err = callbackServer.Serve()
	require.NoError(t, err)
	testFlow(t, flow)
	require.NotNil(t, httpClient)
	userInfo, err := flow.GetUserInfo(httpClient, context.Background())
	require.NoError(t, err)
	fmt.Println(userInfo)
	callbackServer.Shutdown(context.Background())
}

func testFlow(t *testing.T, flow oauth2client.AuthorizationFlow) {
	err := flow.Authenticate()
	require.NoError(t, err)
}

func init() {
	log.InitDefault()
}
