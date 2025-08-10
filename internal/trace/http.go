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

package trace

import (
	"net"
	"net/http"
	"strings"
)

func GetHttpRequestRemoteIP(r *http.Request) string {
	remoteIPHeaders := []string{
		"True-Client-IP",
		"X-Real-IP",
		"X-Forwarded-For",
	}
	for _, remoteIPHeader := range remoteIPHeaders {
		remoteIP := r.Header.Get(remoteIPHeader)
		if remoteIP != "" {
			i := strings.Index(remoteIP, ",")
			if i >= 0 {
				remoteIP = remoteIP[:i]
			}
			if remoteIP != "" {
				return remoteIP
			}
		}
	}
	remoteAddr := r.RemoteAddr
	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = remoteAddr
	}
	return remoteIP
}
