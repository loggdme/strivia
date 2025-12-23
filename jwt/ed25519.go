package jwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

var (
	ErrEd25519Verification = errors.New("jwt-ed25519: verification error")
	ErrNotEdPrivateKey     = errors.New("jwt-ed25519: key is not a valid Ed25519 private key")
	ErrNotEdPublicKey      = errors.New("jwt-ed25519: key is not a valid Ed25519 public key")
)

type PrivateKey ed25519.PrivateKey
type PublicKey ed25519.PublicKey

func VerifyEd25519(signingString string, sig []byte, key *PublicKey) error {
	publicKey := ed25519.PublicKey(*key)

	if len(*key) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}

	if !ed25519.Verify(publicKey, []byte(signingString), sig) {
		return ErrEd25519Verification
	}

	return nil
}

func SignEd25519(signingString string, key *PrivateKey) ([]byte, error) {
	privateKey := ed25519.PrivateKey(*key)

	if _, ok := privateKey.Public().(ed25519.PublicKey); !ok {
		return nil, ErrInvalidKey
	}

	sig, err := privateKey.Sign(rand.Reader, []byte(signingString), crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func ParseEd25519PrivateKey(base64Key string) (PrivateKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, err
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	pkey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrNotEdPrivateKey
	}

	return PrivateKey(pkey), nil
}

func ParseEd25519PublicKey(base64Key string) (PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, err
	}

	parsedKey, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}

	pkey, ok := parsedKey.(ed25519.PublicKey)
	if !ok {
		return nil, ErrNotEdPublicKey
	}

	return PublicKey(pkey), nil
}
