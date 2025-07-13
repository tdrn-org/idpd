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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/tdrn-org/idpd/internal/server/database"
)

func SigningKeyForAlgorithm(algorithm jose.SignatureAlgorithm, passivation int64, expiration int64) (*database.SigningKey, error) {
	var privateKey any
	var publicKey any
	var err error
	switch algorithm {
	case jose.RS256:
		privateKey, publicKey, err = generateRSASigningKey(2048)
	case jose.ES256:
		privateKey, publicKey, err = generateECDSASigningKey(elliptic.P256())
	case jose.PS256:
		privateKey, publicKey, err = generateRSASigningKey(2048)
	default:
		err = fmt.Errorf("unsupported signature key algorithm: %s", algorithm)
	}
	if err != nil {
		return nil, err
	}
	signingKey, err := database.NewSigningKey(string(algorithm), privateKey, publicKey, passivation, expiration)
	if err != nil {
		return nil, err
	}
	return signingKey, nil
}

func generateRSASigningKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key (cause: %w)", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateECDSASigningKey(c elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key (cause: %w)", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}
