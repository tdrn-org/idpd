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
	"net/http"

	"github.com/tdrn-org/idpd/internal/server"
)

func (s *Server) handleUserMock(w http.ResponseWriter, r *http.Request, subject string, password string, remember bool) {
	id := r.URL.Query().Get("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	verifyHandler := server.MockVerifyHandler()
	_, err := s.oauth2Provider.Authenticate(r.Context(), id, subject, password, verifyHandler, remember)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	redirectURL, err := s.oauth2Provider.Verify(r.Context(), id, subject, verifyHandler, "")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
