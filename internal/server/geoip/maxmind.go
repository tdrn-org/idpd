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

package geoip

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/oschwald/maxminddb-golang/v2"
)

type MaxMindDBLocation struct {
	Country struct {
		Names struct {
			EN string `maxminddb:"en"`
		} `maxminddb:"names"`
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names struct {
			EN string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  *float64 `maxminddb:"latitude"`
		Longitude *float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

func (l *MaxMindDBLocation) toLookupResult(host string) (*Location, error) {
	if l.Country.Names.EN == "" || l.Country.ISOCode == "" || l.City.Names.EN == "" {
		return NoLocation, nil
	}
	location := &Location{
		Host:        host,
		Country:     l.Country.Names.EN,
		CountryCode: l.Country.ISOCode,
		City:        l.City.Names.EN,
		Lat:         *l.Location.Latitude,
		Lon:         *l.Location.Longitude,
	}
	return location, nil
}

type MaxMindDBProvider struct {
	reader *maxminddb.Reader
}

const maxMindDBProviderName string = "MaxMindDb"

func OpenMaxMindDB(path string) (*MaxMindDBProvider, error) {
	slog.Debug("opening location database...", slog.String("provider", maxMindDBProviderName), slog.String("path", path))
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open location database '%s' (cause: %w)", path, err)
	}
	provider := &MaxMindDBProvider{
		reader: reader,
	}
	return provider, nil
}

func (p *MaxMindDBProvider) Name() string {
	return maxMindDBProviderName
}

func (p *MaxMindDBProvider) Lookup(host string, addr netip.Addr) (*Location, error) {
	result := p.reader.Lookup(addr)
	if !result.Found() {
		return NoLocation, nil
	}
	location := &MaxMindDBLocation{}
	err := result.Decode(location)
	if err != nil {
		return NoLocation, fmt.Errorf("failed to decode lookup result for addr: %s (cause: %w)", addr.String(), err)
	}
	return location.toLookupResult(host)
}

func (p *MaxMindDBProvider) Close() error {
	return p.reader.Close()
}
