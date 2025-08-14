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

package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
)

type AsymetricKeyType string

const (
	AsymetricKeyTypeRSA2048   AsymetricKeyType = "RSA-2048"
	AsymetricKeyTypeECDSAP256 AsymetricKeyType = "ECDSA-P256"
)

type AsymetricKey struct {
	keyType    AsymetricKeyType
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
}

func NewAsymetricKey(keyType AsymetricKeyType) (*AsymetricKey, error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	var err error
	switch keyType {
	case AsymetricKeyTypeRSA2048:
		privateKey, publicKey, err = GenerateRSAKeys(2048)
	case AsymetricKeyTypeECDSAP256:
		privateKey, publicKey, err = GenerateECDSAKeys(elliptic.P256())
	default:
		err = fmt.Errorf("unrecognized asymetric key type: '%s'", string(keyType))
	}
	if err != nil {
		return nil, err
	}
	key := &AsymetricKey{
		keyType:    keyType,
		privateKey: privateKey,
		publicKey:  publicKey,
	}
	return key, nil
}

func (k *AsymetricKey) KeyType() AsymetricKeyType {
	return k.keyType
}

func (k *AsymetricKey) PrivateKey() crypto.PrivateKey {
	return k.privateKey
}

func (k *AsymetricKey) PublicKey() crypto.PublicKey {
	return k.publicKey
}

func MarshalPrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key (cause: %w)", err)
	}
	return privateKeyBytes, nil
}

func UnmarshalPrivateKey(b []byte) (crypto.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key (cause: %w)", err)
	}
	return privateKey, nil
}

func MarshalPublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key (cause: %w)", err)
	}
	return publicKeyBytes, nil
}

func UnmarshalPublicKey(b []byte) (crypto.PublicKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key (cause: %w)", err)
	}
	return publicKey, nil
}

func GenerateRSAKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key (cause: %w)", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

func GenerateECDSAKeys(c elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key (cause: %w)", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

type SymetricKeyType string

const (
	SymetricKeyTypeAES256SHA256 SymetricKeyType = "aes-256+sha256"
)

type SymetricKeyData interface {
	KeyType() SymetricKeyType
	HashKey() []byte
	BlockKey() []byte
}

type SymetricKey struct {
	keyType   SymetricKeyType
	hashKey   []byte
	hashFunc  func() hash.Hash
	blockKey  []byte
	blockFunc func([]byte) (cipher.Block, error)
	block     cipher.Block
}

func NewSymetricKey(keyType SymetricKeyType) (*SymetricKey, error) {
	var hashKey []byte
	var hashFunc func() hash.Hash
	var blockKey []byte
	var blockFunc func([]byte) (cipher.Block, error)
	var err error
	switch keyType {
	case SymetricKeyTypeAES256SHA256:
		hashKey, hashFunc, err = GenerateSHA256Hash()
		if err == nil {
			blockKey, blockFunc, err = GenerateAESCipher(32)
		}
	default:
		err = fmt.Errorf("unrecognized symetric key type: '%s'", string(keyType))
	}
	if err != nil {
		return nil, err
	}
	block, err := blockFunc(blockKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate block cipher for symetric key: %s (cause: %w)", keyType, err)
	}
	key := &SymetricKey{
		keyType:   keyType,
		hashKey:   hashKey,
		hashFunc:  hashFunc,
		blockKey:  blockKey,
		blockFunc: blockFunc,
		block:     block,
	}
	return key, nil
}

func NewSymetricKeyFromData(data SymetricKeyData) (*SymetricKey, error) {
	keyType := data.KeyType()
	var hashFunc func() hash.Hash
	var blockFunc func([]byte) (cipher.Block, error)
	var err error
	switch keyType {
	case SymetricKeyTypeAES256SHA256:
		hashFunc = SHA256HashFunc()
		blockFunc = AESCipherBlockFunc()
	default:
		err = fmt.Errorf("unrecognized symetric key type: '%s'", string(keyType))
	}
	if err != nil {
		return nil, err
	}
	blockKey := data.BlockKey()
	block, err := blockFunc(blockKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate block cipher for symetric key: %s (cause: %w)", keyType, err)
	}
	key := &SymetricKey{
		keyType:   keyType,
		hashKey:   data.HashKey(),
		hashFunc:  hashFunc,
		blockKey:  blockKey,
		blockFunc: blockFunc,
		block:     block,
	}
	return key, nil
}

func (k *SymetricKey) KeyType() SymetricKeyType {
	return k.keyType
}

func (k *SymetricKey) HashKey() []byte {
	return k.hashKey
}

func (k *SymetricKey) BlockKey() []byte {
	return k.blockKey
}

func (k *SymetricKey) Encrypt(s string) (string, error) {
	plaintext := []byte(s)
	blockSize := k.block.BlockSize()
	ciphertext := make([]byte, blockSize+len(plaintext))
	iv := ciphertext[:blockSize]
	err := ReadRandomBytes(iv)
	if err != nil {
		return "", err
	}
	stream := cipher.NewCTR(k.block, iv)
	stream.XORKeyStream(ciphertext[blockSize:], plaintext)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (k *SymetricKey) Decrypt(s string) (string, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted string (cause: %w)", err)
	}
	blockSize := k.block.BlockSize()
	plaintextLen := len(ciphertext) - blockSize
	if plaintextLen <= 0 {
		return "", fmt.Errorf("invalid encrypted string")
	}
	iv := ciphertext[:blockSize]
	stream := cipher.NewCTR(k.block, iv)
	plaintext := make([]byte, plaintextLen)
	stream.XORKeyStream(plaintext, ciphertext[blockSize:])
	return string(plaintext), nil
}

func ReadRandomBytes(bytes []byte) error {
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return fmt.Errorf("failed generate random bytes (cause: %w)", err)
	}
	return nil
}

func GenerateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	err := ReadRandomBytes(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func AESCipherBlockFunc() func([]byte) (cipher.Block, error) {
	return aes.NewCipher
}

func GenerateAESCipher(size int) ([]byte, func([]byte) (cipher.Block, error), error) {
	key, err := GenerateRandomBytes(size)
	if err != nil {
		return nil, nil, err
	}
	return key, aes.NewCipher, nil
}

func SHA256HashFunc() func() hash.Hash {
	return sha256.New
}

func GenerateSHA256Hash() ([]byte, func() hash.Hash, error) {
	key, err := GenerateRandomBytes(64)
	if err != nil {
		return nil, nil, err
	}
	return key, sha256.New, nil
}
