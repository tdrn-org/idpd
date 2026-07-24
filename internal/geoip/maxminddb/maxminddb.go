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

package maxminddb

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/netip"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/tdrn-org/idpd/internal/geoip"
	"golang.org/x/text/language"
)

const ProviderName geoip.ProviderName = "maxminddb"

type Config struct {
	File string
}

func (c *Config) ProviderName() geoip.ProviderName {
	return ProviderName
}

type maxMindDB struct {
	config *Config
	reader *maxminddb.Reader
	logger *slog.Logger
}

func open(config geoip.ProviderConfig) (geoip.Provider, error) {
	maxMindDBConfig, ok := config.(*Config)
	if !ok {
		return nil, fmt.Errorf("not a MaxMindDB configuration")
	}
	logger := slog.With(slog.String("geoip", fmt.Sprintf("%s/%s", maxMindDBConfig.ProviderName(), maxMindDBConfig.File)))
	logger.Debug("opening MaxMindDB...")
	reader, err := maxminddb.Open(maxMindDBConfig.File)
	if err != nil {
		return nil, fmt.Errorf("failed to open MaxMind DB '%s' (cause: %w)", maxMindDBConfig.File, err)
	}
	logger.Debug("opened MaxMindDB", slog.String("file", maxMindDBConfig.File), slog.Time("build", reader.Metadata.BuildTime()))
	db := &maxMindDB{
		config: maxMindDBConfig,
		reader: reader,
		logger: logger,
	}
	return db, nil
}

func (db *maxMindDB) Name() geoip.ProviderName {
	return db.config.ProviderName()
}

func (db *maxMindDB) Lookup(_ context.Context, address netip.Addr) (*geoip.Info, error) {
	addressLogger := db.logger.With(slog.String("address", address.String()))
	addressLogger.Debug("looking up up address...")
	result := db.reader.Lookup(address)
	if !result.Found() {
		addressLogger.Debug("address not found")
		return geoip.NoInfo, nil
	}
	location := &maxMindDBLocation{}
	err := result.Decode(location)
	if err != nil {
		return geoip.NoInfo, fmt.Errorf("failed to decode location data (cause: %w)", err)
	}
	addressLogger.Debug("address found")
	return location.ToInfo(), nil
}

func (db *maxMindDB) Close() error {
	return db.reader.Close()
}

type maxMindDBNames struct {
	DE string `maxminddb:"de"`
	EN string `maxminddb:"en"`
}

func (names *maxMindDBNames) Get() map[language.Tag]string {
	return map[language.Tag]string{
		language.German:  names.DE,
		language.English: names.EN,
	}
}

type maxMindDBLocation struct {
	Location struct {
		Latitude  *float64 `maxminddb:"latitude"`
		Lnggitude *float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	City struct {
		Names maxMindDBNames `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		Names   maxMindDBNames `maxminddb:"names"`
		ISOCode string         `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func (l *maxMindDBLocation) ToInfo() *geoip.Info {
	lat := math.NaN()
	if l.Location.Latitude != nil {
		lat = *l.Location.Latitude
	}
	lng := math.NaN()
	if l.Location.Lnggitude != nil {
		lng = *l.Location.Lnggitude
	}
	return &geoip.Info{
		Lat:         lat,
		Lng:         lng,
		City:        l.City.Names.Get(),
		Country:     l.Country.Names.Get(),
		CountryCode: l.Country.ISOCode,
	}
}

func init() {
	geoip.RegisterProvider(ProviderName, open)
}
