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

package idpclient_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/httpserver"
	"github.com/tdrn-org/idpd/idpclient"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestAuthorizationCodeFlow(t *testing.T) {
	t.SkipNow()
	config := &idpclient.AuthorizationCodeFlowConfig[*oidc.IDTokenClaims]{
		Issuer:          "https://login.holger.mobi",
		ClientId:        "idpdtest",
		ClientSecret:    "Secret1234",
		BaseURI:         "http://localhost:9123",
		RedirectURIPath: "/oauth2/authorized",
		AuthURIPath:     "/login",
		Scopes:          []string{"openid", "profile", "email", "groups"},
		EnablePKCE:      false,
	}
	flow, err := config.NewFlow(&http.Client{}, context.Background(), rp.UserinfoCallback(func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		fmt.Println(info)
	}))
	require.NoError(t, err)
	server := &httpserver.Instance{Addr: "localhost:9123"}
	flow.Mount(server)
	err = server.Serve()
	require.NoError(t, err)
	server.WaitStopped()
}
