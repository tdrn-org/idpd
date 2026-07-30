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

package geoip

import (
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"net/url"
)

func AddressURL(template string, address netip.Addr) *url.URL {
	if !address.IsGlobalUnicast() || address.IsPrivate() {
		return nil
	}
	rawURL := fmt.Sprintf(template, address.String())
	url, err := url.Parse(rawURL)
	if err != nil {
		slog.Warn("failed to parse Address URL '%s' (cause: %w)", rawURL, err)
		return nil
	}
	return url
}

func LocationURL(template string, lat, lng float64) *url.URL {
	if math.IsNaN(lat) || math.IsNaN(lng) {
		return nil
	}
	rawURL := fmt.Sprintf(template, lat, lng)
	url, err := url.Parse(rawURL)
	if err != nil {
		slog.Warn("failed to parse Location URL '%s' (cause: %w)", rawURL, err)
		return nil
	}
	return url
}
