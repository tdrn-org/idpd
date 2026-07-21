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
	"context"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/zitadel/saml/pkg/provider/key"
	"github.com/zitadel/saml/pkg/provider/models"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

type providerStorage struct {
	handler *Handler
}

// provider.EntityStorage
func (s *providerStorage) GetCA(context.Context) (*key.CertificateAndKey, error) {
	s.logStub()
	return nil, nil
}

// provider.EntityStorage
func (s *providerStorage) GetMetadataSigningKey(context.Context) (*key.CertificateAndKey, error) {
	s.logStub()
	return nil, nil
}

// provider.AuthStorage
func (s *providerStorage) CreateAuthRequest(context.Context, *samlp.AuthnRequestType, string, string, string, string) (models.AuthRequestInt, error) {
	s.logStub()
	return nil, nil
}

// provider.AuthStorage
func (s *providerStorage) AuthRequestByID(context.Context, string) (models.AuthRequestInt, error) {
	s.logStub()
	return nil, nil
}

// provider.IdentityProviderStorage
func (s *providerStorage) GetEntityByID(ctx context.Context, entityID string) (*serviceprovider.ServiceProvider, error) {
	s.logStub()
	return nil, nil
}

// provider.IdentityProviderStorage
func (s *providerStorage) GetEntityIDByAppID(ctx context.Context, entityID string) (string, error) {
	s.logStub()
	return "", nil
}

// provider.IdentityProviderStorage
func (s *providerStorage) GetResponseSigningKey(context.Context) (*key.CertificateAndKey, error) {
	s.logStub()
	return nil, nil
}

// provider.UserStorage
func (s *providerStorage) SetUserinfoWithUserID(ctx context.Context, applicationID string, userinfo models.AttributeSetter, userID string, attributes []int) (err error) {
	s.logStub()
	return nil
}

// provider.UserStorage
func (s *providerStorage) SetUserinfoWithLoginName(ctx context.Context, userinfo models.AttributeSetter, loginName string, attributes []int) (err error) {
	s.logStub()
	return nil
}

// provider.Storage
func (s *providerStorage) Health(context.Context) error {
	s.logStub()
	return nil
}

func (s *providerStorage) logStub() {
	_, file, line, _ := runtime.Caller(1)
	s.handler.runtime.Logger().Warn("stub call", slog.String("location", fmt.Sprintf("%s:%d", file, line)))
}
