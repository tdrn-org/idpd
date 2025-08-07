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
	"net"
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
		return nil, ErrNotFound
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
	logger *slog.Logger
}

func OpenMaxMindDB(path string) (*MaxMindDBProvider, error) {
	logger := slog.With(slog.String("provider", "MaxMindB"), slog.String("path", path))
	logger.Debug("opening location database...")
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open location database '%s' (cause: %w)", path, err)
	}
	provider := &MaxMindDBProvider{
		reader: reader,
		logger: logger,
	}
	return provider, nil
}

func (p *MaxMindDBProvider) Lookup(host string) (*Location, error) {
	p.logger.Debug("looking up host location", slog.String("host", host))
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup host '%s' (cause: %w)", host, err)
	}
	for _, addr := range addrs {
		lookupAddr, err := netip.ParseAddr(addr)
		if err != nil {
			p.logger.Warn("ignoring host address", slog.String("addr", addr), slog.Any("err", err))
			continue
		}
		result := p.reader.Lookup(lookupAddr)
		if !result.Found() {
			continue
		}
		location := &MaxMindDBLocation{}
		err = result.Decode(location)
		if err != nil {
			p.logger.Warn("ignoring addr decode failure", slog.String("addr", addr), slog.Any("err", err))
			continue
		}
		return location.toLookupResult(host)
	}
	return nil, ErrNotFound
}

func (p *MaxMindDBProvider) Close() error {
	return p.reader.Close()
}
