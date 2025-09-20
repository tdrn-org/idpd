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

package server

import (
	"github.com/tdrn-org/idpd/httpserver"
	"github.com/zitadel/saml/pkg/provider"
)

type SAML2ProviderConfig struct {
}

func (c *SAML2ProviderConfig) NewProvider() (*SAML2Provider, error) {
	return nil, nil
}

type SAML2Provider struct {
	saml2Provider *provider.Provider
}

func (p *SAML2Provider) Scheme() Scheme {
	return SchemeSAML2
}

func (p *SAML2Provider) Mount(handler httpserver.Handler) {

}
