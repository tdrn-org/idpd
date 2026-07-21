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

package saml2

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/config"
	"github.com/tdrn-org/idpd/internal/scheme"
	"github.com/zitadel/saml/pkg/provider"
	"github.com/zitadel/saml/pkg/provider/xml/md"
)

const Name scheme.Name = "saml2"

const (
	metadataPath     string = "/" + string(Name) + "/" + provider.DefaultMetadataEndpoint
	certificatePath  string = "/" + string(Name) + "/" + provider.DefaultCertificateEndpoint
	callbackPath     string = "/" + string(Name) + "/" + provider.DefaultCallbackEndpoint
	singleSignOnPath string = "/" + string(Name) + "/" + provider.DefaultSingleSignOnEndpoint
	singleLogOutPath string = "/" + string(Name) + "/" + provider.DefaultSingleLogOutEndpoint
	attributePath    string = "/" + string(Name) + "/" + provider.DefaultAttributeEndpoint
)

var metdataEndpoint = provider.NewEndpoint(metadataPath)
var certificateEndpoint = provider.NewEndpoint(certificatePath)
var callbackEndpoint = provider.NewEndpoint(callbackPath)
var singleSignOnEndpoint = provider.NewEndpoint(singleSignOnPath)
var singleLogOutEndpoint = provider.NewEndpoint(singleLogOutPath)
var attributeEndpoint = provider.NewEndpoint(attributePath)

type Handler struct {
	runtime       scheme.Runtime
	saml2Provider *provider.Provider
	metadataURL   *url.URL
	logger        *slog.Logger
}

func NewHandler(runtime scheme.Runtime, cfg *config.SAML2Config) (*Handler, error) {
	logger := runtime.Logger().With("scheme", Name)
	issuerURL := runtime.BaseURL()
	metadataURL := issuerURL.JoinPath(metadataPath)
	h := &Handler{
		runtime:     runtime,
		metadataURL: metadataURL,
		logger:      logger,
	}
	providerStorage := &providerStorage{handler: h}
	organizationURL := cfg.OrganizationURL.String()
	if organizationURL == "" {
		organizationURL = issuerURL.String()
	}
	organizationName := cfg.OrganizationName
	if organizationName == "" {
		organizationName = organizationURL
	}
	providerConfig := &provider.Config{
		MetadataConfig: &provider.MetadataConfig{
			// TODO
		},
		IDPConfig: &provider.IdentityProviderConfig{
			MetadataIDPConfig: &provider.MetadataIDPConfig{
				//TODO
			},
			Endpoints: &provider.EndpointConfig{
				Certificate:  &certificateEndpoint,
				Callback:     &callbackEndpoint,
				SingleSignOn: &singleSignOnEndpoint,
				SingleLogOut: &singleLogOutEndpoint,
				Attribute:    &attributeEndpoint,
			},
		},
		Metadata: &metdataEndpoint,
		Organisation: &provider.Organisation{
			Name: organizationName,
			URL:  organizationURL,
		},
		ContactPerson: &provider.ContactPerson{
			ContactType:  md.ContactTypeTypeAdministrative,
			EmailAddress: cfg.ContactEmail,
		},
	}
	providerOpts := make([]provider.Option, 0)
	providerOpts = append(providerOpts, allowInsecure(issuerURL))
	provider, err := provider.NewProvider(
		providerStorage,
		provider.StaticIssuer(issuerURL.String()),
		providerConfig,
		providerOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML2 provider (cause: %w)", err)
	}
	h.saml2Provider = provider
	return h, nil
}

func (h *Handler) Name() scheme.Name {
	return Name
}

func (h *Handler) Mount(instance *httpserver.Instance) {
	httpHandler := h.saml2Provider.HttpHandler()
	instance.Handle(metadataPath, httpHandler)
	instance.Handle(certificatePath, httpHandler)
	instance.Handle(callbackPath, httpHandler)
	instance.Handle(singleSignOnPath, httpHandler)
	instance.Handle(singleLogOutPath, httpHandler)
	instance.Handle(attributePath, httpHandler)
}

func (h *Handler) MetadataURL() *url.URL {
	return h.metadataURL
}

func allowInsecure(issuerURL *url.URL) provider.Option {
	noop := func(_ *provider.Provider) error { return nil }
	if issuerURL.Scheme == "https" {
		return noop
	}
	host := strings.ToLower(issuerURL.Hostname())
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return provider.WithAllowInsecure()
	}
	return noop
}
