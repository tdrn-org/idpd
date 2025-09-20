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
	"fmt"
	"net"
	"net/http"
)

type AccessPolicy interface {
	Allow(remoteIP net.IP) bool
}

func AccessPolicyHandler(handler http.Handler, policy AccessPolicy) http.Handler {
	if policy == nil {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteIP := RemoteIPContextValue(r)
		parsedRemoteIP := net.ParseIP(remoteIP)
		if parsedRemoteIP == nil || !policy.Allow(parsedRemoteIP) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func ParseNetworks(cidrs ...string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse network: '%s' (cause: %w)", cidr, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func AllowNetworks(networks []*net.IPNet) AccessPolicy {
	if len(networks) == 0 {
		return nil
	}
	return &networkAccessPolicy{networks: networks}
}

type networkAccessPolicy struct {
	networks []*net.IPNet
}

func (p *networkAccessPolicy) Allow(remoteIP net.IP) bool {
	for _, network := range p.networks {
		if network.Contains(remoteIP) {
			return true
		}
	}
	return false
}
