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

import "errors"

var ErrNotFound = errors.New("not found")

type Location struct {
	Host        string
	Country     string
	CountryCode string
	City        string
	Lon         float64
	Lat         float64
}

type Provider interface {
	Lookup(host string) (*Location, error)
	Close() error
}

type Cache interface {
	LookupCached(host string) (*Location, bool)
	UpdateCache(host string, location *Location)
	Close() error
}

type LocationService struct {
	provider Provider
	cache    Cache
}

func NewLocationService(provider Provider, cache Cache) *LocationService {
	return &LocationService{
		provider: provider,
		cache:    cache,
	}
}

func (s *LocationService) Lookup(host string) (*Location, error) {
	if s.cache == nil {
		return s.provider.Lookup(host)
	}
	location, cached := s.cache.LookupCached(host)
	if cached {
		return location, nil
	}
	location, err := s.provider.Lookup(host)
	if err != nil {
		return nil, err
	}
	s.cache.UpdateCache(host, location)
	return location, nil
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

func (p *dummyProvider) Lookup(_ string) (*Location, error) {
	return nil, ErrNotFound
}

func (p *dummyProvider) Close() error {
	return nil
}
