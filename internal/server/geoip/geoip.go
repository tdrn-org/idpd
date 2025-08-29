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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/jellydator/ttlcache/v3"
)

type Location struct {
	Host        string
	Country     string
	CountryCode string
	City        string
	Lat         float64
	Lon         float64
}

var NoLocation *Location = &Location{}

type Provider interface {
	Name() string
	Lookup(host string, addr netip.Addr) (*Location, error)
	Close() error
}

type Cache interface {
	LookupCached(host string) *Location
	UpdateCache(host string, location *Location)
	Close() error
}

type LocationService struct {
	provider Provider
	cache    Cache
	mapping  map[*net.IPNet]string
	logger   *slog.Logger
}

func NoMapping() map[*net.IPNet]string {
	return make(map[*net.IPNet]string)
}

func NewLocationService(provider Provider, cache Cache, mapping map[*net.IPNet]string) *LocationService {
	logger := slog.With("geoip", provider.Name())
	return &LocationService{
		provider: provider,
		cache:    cache,
		mapping:  mapping,
		logger:   logger,
	}
}

func (s *LocationService) Lookup(host string) (*Location, error) {
	location := s.cache.LookupCached(host)
	if location != NoLocation {
		return location, nil
	}
	hostAddrs, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup host '%s' (cause: %w)", host, err)
	}
	for _, hostAddr := range hostAddrs {
		addr, err := netip.ParseAddr(hostAddr)
		if err != nil {
			s.logger.Warn("ignoring host address", slog.String("addr", hostAddr), slog.Any("err", err))
			continue
		}
		mappedAddrs := s.mapAddr(addr)
		for _, mappedAddr := range mappedAddrs {
			location, err := s.provider.Lookup(host, mappedAddr)
			if err != nil || location == NoLocation {
				continue
			}
			s.cache.UpdateCache(host, location)
			return location, nil
		}
	}
	return NoLocation, nil
}

func (s *LocationService) mapAddr(addr netip.Addr) []netip.Addr {
	ip := net.IP(addr.AsSlice())
	for network, host := range s.mapping {
		if network.Contains(ip) {
			return s.mapAddrToHost(addr, host)
		}
	}
	return []netip.Addr{addr}
}

func (s *LocationService) mapAddrToHost(addr netip.Addr, host string) []netip.Addr {
	mappedHostAddrs, err := net.LookupHost(host)
	if err != nil {
		s.logger.Warn("failed to lookup mapped host; ignoring mapping", slog.String("host", host), slog.Any("err", err))
		return []netip.Addr{addr}
	}
	mappedAddrs := make([]netip.Addr, 0, len(mappedHostAddrs))
	for _, mappedHostAddr := range mappedHostAddrs {
		mappedAddr, err := netip.ParseAddr(mappedHostAddr)
		if err != nil {
			s.logger.Warn("ignoring mapped host address", slog.String("addr", mappedHostAddr), slog.Any("err", err))
			continue
		}
		mappedAddrs = append(mappedAddrs, mappedAddr)
	}
	if len(mappedAddrs) == 0 {
		return []netip.Addr{addr}
	}
	return mappedAddrs
}

func (s *LocationService) Close() error {
	if s.cache == nil {
		return s.provider.Close()
	}
	return errors.Join(s.provider.Close(), s.cache.Close())
}

func DummyProvider() Provider {
	return &dummyProvider{}
}

type dummyProvider struct{}

func (p *dummyProvider) Name() string {
	return "disabled"
}

func (p *dummyProvider) Lookup(_ string, _ netip.Addr) (*Location, error) {
	return NoLocation, nil
}

func (p *dummyProvider) Close() error {
	return nil
}

const defaultCacheCapacity uint64 = 128

func DefaultCache() Cache {
	cacheOpts := []ttlcache.Option[string, *Location]{
		ttlcache.WithCapacity[string, *Location](defaultCacheCapacity),
		ttlcache.WithTTL[string, *Location](ttlcache.NoTTL),
	}
	cache := ttlcache.New(cacheOpts...)
	return &ttlCache{
		cache: cache,
	}
}

type ttlCache struct {
	cache *ttlcache.Cache[string, *Location]
}

func (c *ttlCache) LookupCached(host string) *Location {
	entry := c.cache.Get(host)
	if entry == nil {
		return NoLocation
	}
	return entry.Value()
}

func (c *ttlCache) UpdateCache(host string, location *Location) {
	c.cache.Set(host, location, ttlcache.DefaultTTL)
}

func (c *ttlCache) Close() error {
	c.cache.DeleteAll()
	return nil
}
