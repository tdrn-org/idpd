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
	"context"
	"net/netip"
)

const NoneProviderName ProviderName = "none"

type None struct{}

func (*None) ProviderName() ProviderName {
	return NoneProviderName
}

type noneProvider struct{}

func (p *noneProvider) Name() ProviderName {
	return NoneProviderName
}

func (p *noneProvider) Lookup(_ context.Context, _ netip.Addr) (*Info, error) {
	return NoInfo, nil
}

func (p *noneProvider) Close() error {
	return nil
}

func init() {
	RegisterProvider(NoneProviderName, func(_ ProviderConfig) (Provider, error) {
		return &noneProvider{}, nil
	})
}
