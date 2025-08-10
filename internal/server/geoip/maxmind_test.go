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
	"github.com/tdrn-org/idpd/internal/server/geoip"
)

func TestMaxMindDBProvider(t *testing.T) {
	host, hostAddrs, path := initHostDB(t)
	provider, err := geoip.OpenMaxMindDB(path)
	require.NoError(t, err)

	for _, hostAddr := range hostAddrs {
		location, err := provider.Lookup(host, hostAddr)
		require.NoError(t, err)
		require.NotNil(t, location)
		require.NotEmpty(t, location.Country)
		require.NotEmpty(t, location.CountryCode)
	}

	location, err := provider.Lookup("localhost", netip.IPv6Loopback())
	require.NoError(t, err)
	require.Equal(t, geoip.NoLocation, location)

	err = provider.Close()
	require.NoError(t, err)
}

func TestMaxMindDBService(t *testing.T) {
	host, _, path := initHostDB(t)
	provider, err := geoip.OpenMaxMindDB(path)
	require.NoError(t, err)

	mapping := map[*net.IPNet]string{
		&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 255, 255)}: host,
	}
	service := geoip.NewLocationService(provider, geoip.DefaultCache(), mapping)

	hostLocation, err := service.Lookup(host)
	require.NoError(t, err)
	require.NotNil(t, hostLocation)
	require.NotEmpty(t, hostLocation.Country)
	require.NotEmpty(t, hostLocation.CountryCode)
	require.NotEmpty(t, hostLocation.City)

	localhostLocation, err := service.Lookup("localhost")
	require.NoError(t, err)
	require.Equal(t, localhostLocation.Host, "localhost")
	require.Equal(t, hostLocation.Country, localhostLocation.Country)
	require.Equal(t, hostLocation.CountryCode, localhostLocation.CountryCode)
	require.Equal(t, hostLocation.City, localhostLocation.City)
	require.Equal(t, hostLocation.Lat, localhostLocation.Lat)
	require.Equal(t, hostLocation.Lon, localhostLocation.Lon)

	err = service.Close()
	require.NoError(t, err)
}

func initHostDB(t *testing.T) (string, []netip.Addr, string) {
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "test.mmdb"))
	require.NoError(t, err)
	defer file.Close()
	host, err := os.Hostname()
	require.NoError(t, err)
	addrs, err := net.LookupHost(host)
	require.NoError(t, err)
	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "test",
		IncludeReservedNetworks: true,
	})
	require.NoError(t, err)
	hostAddrs := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		hostAddr, err := netip.ParseAddr(addr)
		require.NoError(t, err)
		hostAddrs = append(hostAddrs, hostAddr)
		var cidrSuffix string
		if hostAddr.Is4() {
			cidrSuffix = "/24"
		} else {
			cidrSuffix = "/128"
		}
		_, network, err := net.ParseCIDR(addr + cidrSuffix)
		require.NoError(t, err)
		record := mmdbtype.Map{
			"country": mmdbtype.Map{
				"names": mmdbtype.Map{
					"en": mmdbtype.String("devCountry"),
				},
				"iso_code": mmdbtype.String("dv"),
			},
			"city": mmdbtype.Map{
				"names": mmdbtype.Map{
					"en": mmdbtype.String("devCity"),
				},
			},
			"location": mmdbtype.Map{
				"latitude":  mmdbtype.Float64(0.0),
				"longitude": mmdbtype.Float64(0.0),
			},
		}
		writer.Insert(network, record)
	}
	_, err = writer.WriteTo(file)
	require.NoError(t, err)
	return host, hostAddrs, file.Name()
}
