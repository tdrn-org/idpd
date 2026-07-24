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

package geoip_test

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/idpd/internal/geoip"
	"github.com/tdrn-org/idpd/internal/geoip/maxminddb"
	"golang.org/x/text/language"
)

const testLat float64 = 0.1
const testLng float64 = -0.1
const testCity string = "Test city"
const testCountry string = "Test country"
const testCountryCode string = "tc"

func TestNoneProvider(t *testing.T) {
	provider, err := geoip.Open(&geoip.None{}, nil)
	require.NoError(t, err)

	// Run tests
	runProviderTests(t, geoip.NoneProviderName, provider, nil)
}

func TestMaxMindDBProvider(t *testing.T) {
	dbFile, addrs := createTestMaxMindDB(t)
	config := &maxminddb.Config{
		File: dbFile,
	}
	db, err := geoip.Open(config, nil)
	require.NoError(t, err)
	require.NotNil(t, db)

	// Run tests
	runProviderTests(t, maxminddb.ProviderName, db, addrs)

	// Close database
	err = db.Close()
	require.NoError(t, err)
}

func runProviderTests(t *testing.T, name geoip.ProviderName, provider geoip.Provider, addrs []netip.Addr) {
	// Provider name
	providerName := provider.Name()
	require.Equal(t, name, providerName)

	if len(addrs) > 0 {
		// Lookup known address
		addr := addrs[0]
		location, err := provider.Lookup(t.Context(), addr)
		require.NoError(t, err)
		require.NotNil(t, location)
		require.Equal(t, testLat, location.Lat)
		require.Equal(t, testLng, location.Lng)
		require.Equal(t, testCity, location.City[language.English])
		require.Equal(t, testCountry, location.Country[language.English])
		require.Equal(t, testCountryCode, location.CountryCode)
	}

	// Lookup unknown address
	location, err := provider.Lookup(t.Context(), netip.MustParseAddr("1.2.3.4"))
	require.NoError(t, err)
	require.Equal(t, geoip.NoInfo, location)
}

func createTestMaxMindDB(t *testing.T) (string, []netip.Addr) {
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "test.mmdb"))
	require.NoError(t, err)
	defer file.Close()
	addrs := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.IPv6Loopback(),
	}
	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "test",
		IncludeReservedNetworks: true,
	})
	require.NoError(t, err)
	for _, addr := range addrs {
		var cidrSuffix string
		if addr.Is4() {
			cidrSuffix = "/24"
		} else {
			cidrSuffix = "/128"
		}
		_, network, err := net.ParseCIDR(addr.String() + cidrSuffix)
		require.NoError(t, err)
		record := mmdbtype.Map{
			"location": mmdbtype.Map{
				"latitude":  mmdbtype.Float64(testLat),
				"longitude": mmdbtype.Float64(testLng),
			},
			"city": mmdbtype.Map{
				"names": mmdbtype.Map{
					"en": mmdbtype.String(testCity),
				},
			},
			"country": mmdbtype.Map{
				"names": mmdbtype.Map{
					"en": mmdbtype.String(testCountry),
				},
				"iso_code": mmdbtype.String(testCountryCode),
			},
		}
		writer.Insert(network, record)
	}
	_, err = writer.WriteTo(file)
	require.NoError(t, err)
	return file.Name(), addrs
}
