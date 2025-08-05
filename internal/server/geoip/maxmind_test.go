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
	host, path := initHostDB(t)
	provider, err := geoip.OpenMaxMindDB(path)
	require.NoError(t, err)

	location, err := provider.Lookup(host)
	require.NoError(t, err)
	require.NotNil(t, location)
	require.NotEmpty(t, location.Country)
	require.NotEmpty(t, location.CountryCode)

	_, err = provider.Lookup("localhost")
	require.ErrorIs(t, err, geoip.ErrNotFound)

	err = provider.Close()
	require.NoError(t, err)
}

func TestMaxMindDBService(t *testing.T) {
	host, path := initHostDB(t)
	provider, err := geoip.OpenMaxMindDB(path)
	require.NoError(t, err)
	service := geoip.NewLocationService(provider, nil)

	location, err := service.Lookup(host)
	require.NoError(t, err)
	require.NotNil(t, location)
	require.NotEmpty(t, location.Country)
	require.NotEmpty(t, location.CountryCode)

	_, err = service.Lookup("localhost")
	require.ErrorIs(t, err, geoip.ErrNotFound)

	err = service.Close()
	require.NoError(t, err)
}

func initHostDB(t *testing.T) (string, string) {
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "test.mmdb"))
	require.NoError(t, err)
	defer file.Close()
	host, err := os.Hostname()
	require.NoError(t, err)
	hostAddrs, err := net.LookupHost(host)
	require.NoError(t, err)
	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "test",
		IncludeReservedNetworks: true,
	})
	require.NoError(t, err)
	for _, hostAddr := range hostAddrs {
		addr, err := netip.ParseAddr(hostAddr)
		require.NoError(t, err)
		var cidrSuffix string
		if addr.Is4() {
			cidrSuffix = "/24"
		} else {
			cidrSuffix = "/128"
		}
		_, network, err := net.ParseCIDR(hostAddr + cidrSuffix)
		require.NoError(t, err)
		record := mmdbtype.Map{
			"country": mmdbtype.Map{
				"names": mmdbtype.Map{
					"en": mmdbtype.String("dev"),
				},
				"iso_code": mmdbtype.String("dv"),
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
	return host, file.Name()
}
