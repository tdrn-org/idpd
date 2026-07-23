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
)

type JoseSigningKey struct {
	ID         string
	Algorithm  jose.SignatureAlgorithm
	PrivateKey any
}

func NewSigningKey(algorithm jose.SignatureAlgorithm) (*JoseSigningKey, error) {
	var key any
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
	sigingKey := &JoseSigningKey{
		Algorithm:  algorithm,
		PrivateKey: key,
	}
	return sigingKey, nil
}

func (signingKey *JoseSigningKey) PublicKey() (any, error) {
	switch key := signingKey.PrivateKey.(type) {
	case []byte:
		return key, nil
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	default:
		return nil, fmt.Errorf("unrecognized key type %T", signingKey.PrivateKey)
	}
}

func (signingKey *JoseSigningKey) MarshalSigningKey() (jose.SignatureAlgorithm, []byte, error) {
	switch key := signingKey.PrivateKey.(type) {
	case []byte:
		return signingKey.Algorithm, key, nil
	case *rsa.PrivateKey:
		return marshalPrivateSigningKey(signingKey.Algorithm, key)
	case *ecdsa.PrivateKey:
		return marshalPrivateSigningKey(signingKey.Algorithm, key)
	case ed25519.PrivateKey:
		return marshalPrivateSigningKey(signingKey.Algorithm, key)
	default:
		return "", nil, fmt.Errorf("unrecognized key type %T", signingKey.PrivateKey)
	}
}

func marshalPrivateSigningKey(algorithm jose.SignatureAlgorithm, privateKey crypto.PrivateKey) (jose.SignatureAlgorithm, []byte, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal private key (cause: %w)", err)
	}
	return algorithm, privateKeyBytes, nil
}

func UnmarshalSigningKey(algorithm jose.SignatureAlgorithm, encoded []byte) (*JoseSigningKey, error) {
	var key interface{}
	var err error

	switch algorithm {
	case jose.HS256:
		key, err = unmarshalRawSigningKey(encoded, 32)
	case jose.HS384:
		key, err = unmarshalRawSigningKey(encoded, 48)
	case jose.HS512:
		key, err = unmarshalRawSigningKey(encoded, 64)
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key, err = unmarshalPrivateSigningKey(encoded)
	case jose.ES256:
		key, err = unmarshalPrivateSigningKey(encoded)
	case jose.ES384:
		key, err = unmarshalPrivateSigningKey(encoded)
	case jose.ES512:
		key, err = unmarshalPrivateSigningKey(encoded)
	case jose.EdDSA:
		key, err = unmarshalPrivateSigningKey(encoded)
	default:
		err = fmt.Errorf("unsupported signature algorithm '%s'", algorithm)
	}
	if err != nil {
		return nil, err
	}
	sigingKey := &JoseSigningKey{
		Algorithm:  algorithm,
		PrivateKey: key,
	}
	return sigingKey, nil
}

func unmarshalRawSigningKey(encoded []byte, expectedLen int) ([]byte, error) {
	encodedLen := len(encoded)
	if encodedLen != expectedLen {
		return nil, fmt.Errorf("unexpected raw key lenght %d (expected: %d)", encodedLen, expectedLen)
	}
	return encoded, nil
}

func unmarshalPrivateSigningKey(encoded []byte) (crypto.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key (cause: %w)", err)
	}
	return privateKey, nil
}
