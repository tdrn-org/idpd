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

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/tdrn-org/idpd/internal/domain"
)

func NewSigningKey(algorithm jose.SignatureAlgorithm) (*domain.SigningKey, error) {
	var key interface{}
	var err error

	switch algorithm {
	case jose.HS256:
		key = make([]byte, 32)
		_, err = rand.Read(key.([]byte))
	case jose.HS384:
		key = make([]byte, 48)
		_, err = rand.Read(key.([]byte))
	case jose.HS512:
		key = make([]byte, 64)
		_, err = rand.Read(key.([]byte))
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case jose.ES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.ES384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jose.ES512:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case jose.EdDSA:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		err = fmt.Errorf("unsupported signature algorithm '%s'", algorithm)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generated signature key (cause: %w)", err)
	}
	sigingKey := &domain.SigningKey{
		Algorithm: algorithm,
		Key:       key,
	}
	return sigingKey, nil
}

func MarshalSigningKey(signingKey *domain.SigningKey) (jose.SignatureAlgorithm, []byte, error) {
	switch key := signingKey.Key.(type) {
	case []byte:
		return signingKey.Algorithm, key, nil
	case *rsa.PrivateKey:
		return marshalPrivateKey(signingKey.Algorithm, key)
	case *ecdsa.PrivateKey:
		return marshalPrivateKey(signingKey.Algorithm, key)
	case ed25519.PrivateKey:
		return marshalPrivateKey(signingKey.Algorithm, key)
	default:
		return "", nil, fmt.Errorf("unrecognized key type %T", signingKey.Key)
	}
}

func marshalPrivateKey(algorithm jose.SignatureAlgorithm, privateKey crypto.PrivateKey) (jose.SignatureAlgorithm, []byte, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal private key (cause: %w)", err)
	}
	return algorithm, privateKeyBytes, nil
}

func UnmarshalSigningKey(algorithm jose.SignatureAlgorithm, encoded []byte) (*domain.SigningKey, error) {
	var key interface{}
	var err error

	switch algorithm {
	case jose.HS256:
		key, err = unmarshalRawKey(encoded, 32)
	case jose.HS384:
		key, err = unmarshalRawKey(encoded, 48)
	case jose.HS512:
		key, err = unmarshalRawKey(encoded, 64)
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key, err = unmarshalPrivateKey(encoded)
	case jose.ES256:
		key, err = unmarshalPrivateKey(encoded)
	case jose.ES384:
		key, err = unmarshalPrivateKey(encoded)
	case jose.ES512:
		key, err = unmarshalPrivateKey(encoded)
	case jose.EdDSA:
		key, err = unmarshalPrivateKey(encoded)
	default:
		err = fmt.Errorf("unsupported signature algorithm '%s'", algorithm)
	}
	if err != nil {
		return nil, err
	}
	sigingKey := &domain.SigningKey{
		Algorithm: algorithm,
		Key:       key,
	}
	return sigingKey, nil
}

func unmarshalRawKey(encoded []byte, expectedLen int) ([]byte, error) {
	encodedLen := len(encoded)
	if encodedLen != expectedLen {
		return nil, fmt.Errorf("unexpected raw key lenght %d (expected: %d)", encodedLen, expectedLen)
	}
	return encoded, nil
}

func unmarshalPrivateKey(encoded []byte) (crypto.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key (cause: %w)", err)
	}
	return privateKey, nil
}
