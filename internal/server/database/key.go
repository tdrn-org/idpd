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
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	serverconf "github.com/tdrn-org/idpd/internal/server/conf"
	servercrypto "github.com/tdrn-org/idpd/internal/server/crypto"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type SigningKey struct {
	ID         string
	Algorithm  string
	PrivateKey []byte
	PublicKey  []byte
	CreateTime int64
}

func NewSigningKeyForAlgorithm(algorithm jose.SignatureAlgorithm) (*SigningKey, error) {
	var key *servercrypto.AsymetricKey
	var err error
	switch algorithm {
	case jose.RS256, jose.PS256:
		key, err = servercrypto.NewAsymetricKey(servercrypto.AsymetricKeyTypeRSA2048)
	case jose.ES256:
		key, err = servercrypto.NewAsymetricKey(servercrypto.AsymetricKeyTypeECDSAP256)
	default:
		err = fmt.Errorf("unsupported signature key algorithm: %s", algorithm)
	}
	if err != nil {
		return nil, err
	}
	privateKeyBytes, err := servercrypto.MarshalPrivateKey(key.PrivateKey())
	if err != nil {
		return nil, err
	}
	publicKeyBytes, err := servercrypto.MarshalPublicKey(key.PublicKey())
	if err != nil {
		return nil, err
	}
	signingKey := &SigningKey{
		ID:         uuid.NewString(),
		Algorithm:  string(algorithm),
		PrivateKey: privateKeyBytes,
		PublicKey:  publicKeyBytes,
		CreateTime: time.Now().UnixMicro(),
	}
	return signingKey, nil
}

func (k *SigningKey) IsActive(now int64) bool {
	return time.UnixMicro(now).Add(-1*serverconf.LookupRuntime().SigningKeyLifetime).UnixMicro() <= k.CreateTime
}

func (k *SigningKey) OpSigningKey() (op.SigningKey, error) {
	privateKey, err := servercrypto.UnmarshalPrivateKey(k.PrivateKey)
	if err != nil {
		return nil, err
	}
	key := &opSigningKey{
		id:                 k.ID,
		signatureAlgorithm: jose.SignatureAlgorithm(k.Algorithm),
		key:                privateKey,
	}
	return key, nil
}

func (k *SigningKey) OpKey() (op.Key, error) {
	publicKey, err := servercrypto.UnmarshalPublicKey(k.PublicKey)
	if err != nil {
		return nil, err
	}
	key := &opKey{
		id:        k.ID,
		algorithm: jose.SignatureAlgorithm(k.Algorithm),
		use:       "sig",
		key:       publicKey,
	}
	return key, nil
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

type EncryptionKey struct {
	ID         string
	KeyGroup   string
	KeyType    string
	HashKey    []byte
	BlockKey   []byte
	CreateTime int64
}

func NewEncryptionKey(keyType servercrypto.SymetricKeyType, keyGroup string) (*EncryptionKey, error) {
	key, err := servercrypto.NewSymetricKey(keyType)
	if err != nil {
		return nil, err
	}
	encryptionKey := &EncryptionKey{
		ID:         uuid.NewString(),
		KeyGroup:   keyGroup,
		KeyType:    string(keyType),
		HashKey:    key.HashKey(),
		BlockKey:   key.BlockKey(),
		CreateTime: time.Now().UnixMicro(),
	}
	return encryptionKey, nil
}

func (k *EncryptionKey) KeyData() servercrypto.SymetricKeyData {
	return &encryptionKeyData{key: k}
}

func (k *EncryptionKey) OpCrypto() (op.Crypto, error) {
	key, err := servercrypto.NewSymetricKeyFromData(k.KeyData())
	if err != nil {
		return nil, err
	}
	return &opCrypto{key: key}, nil
}

type encryptionKeyData struct {
	key *EncryptionKey
}

func (d *encryptionKeyData) KeyType() servercrypto.SymetricKeyType {
	return servercrypto.SymetricKeyType(d.key.KeyType)
}

func (d *encryptionKeyData) HashKey() []byte {
	return d.key.HashKey
}

func (d *encryptionKeyData) BlockKey() []byte {
	return d.key.BlockKey
}

type opCrypto struct {
	key *servercrypto.SymetricKey
}

func (c *opCrypto) Encrypt(s string) (string, error) {
	return c.key.Encrypt(s)
}

func (c *opCrypto) Decrypt(s string) (string, error) {
	return c.key.Decrypt(s)
}

type EncryptionKeys []*EncryptionKey
