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

package database

import (
	"crypto/x509"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type SigningKey struct {
	ID          string
	Algorithm   string
	PrivateKey  []byte
	PublicKey   []byte
	Passivation int64
	Expiry      int64
}

func NewSigningKey(algorithm string, privateKey any, publicKey any, passivation int64, expiry int64) (*SigningKey, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key (cause: %w)", err)
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key (cause: %w)", err)
	}
	return &SigningKey{
		ID:          uuid.NewString(),
		Algorithm:   algorithm,
		PrivateKey:  privateKeyBytes,
		PublicKey:   publicKeyBytes,
		Passivation: passivation,
		Expiry:      expiry,
	}, nil
}

func (k *SigningKey) IsActive(now int64) bool {
	return now <= k.Passivation
}

func (k *SigningKey) OpSigningKey() (op.SigningKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(k.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (cause: %w)", err)
	}
	return &opSigningKey{
		id:                 k.ID,
		signatureAlgorithm: jose.SignatureAlgorithm(k.Algorithm),
		key:                key,
	}, nil
}

func (k *SigningKey) OpKey() (op.Key, error) {
	key, err := x509.ParsePKIXPublicKey(k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key (cause: %w)", err)
	}
	return &opKey{
		id:        k.ID,
		algorithm: jose.SignatureAlgorithm(k.Algorithm),
		use:       "sig",
		key:       key,
	}, nil
}

type opSigningKey struct {
	id                 string
	signatureAlgorithm jose.SignatureAlgorithm
	key                any
}

func (k *opSigningKey) ID() string {
	return k.id
}

func (k *opSigningKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return k.signatureAlgorithm
}

func (k *opSigningKey) Key() any {
	return k.key
}

type opKey struct {
	id        string
	algorithm jose.SignatureAlgorithm
	use       string
	key       any
}

func (k *opKey) ID() string {
	return k.id
}

func (k *opKey) Algorithm() jose.SignatureAlgorithm {
	return k.algorithm
}

func (k *opKey) Use() string {
	return k.use
}

func (k *opKey) Key() any {
	return k.key
}

type SigningKeys []*SigningKey
