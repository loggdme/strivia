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

func VerifyEd25519(signingString string, sig []byte, key any) error {
	var ed25519Key ed25519.PublicKey
	var ok bool

	if ed25519Key, ok = key.(ed25519.PublicKey); !ok {
		return ErrInvalidKeyType
	}

	if len(ed25519Key) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}

	if !ed25519.Verify(ed25519Key, []byte(signingString), sig) {
		return ErrEd25519Verification
	}

	return nil
}

func SignEd25519(signingString string, key any) ([]byte, error) {
	var ed25519Key crypto.Signer
	var ok bool

	if ed25519Key, ok = key.(crypto.Signer); !ok {
		return nil, ErrInvalidKeyType
	}

	if _, ok := ed25519Key.Public().(ed25519.PublicKey); !ok {
		return nil, ErrInvalidKey
	}

	sig, err := ed25519Key.Sign(rand.Reader, []byte(signingString), crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func ParseEd25519PrivateKey(base64Key string) (crypto.PrivateKey, error) {
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

	return pkey, nil
}

func ParseEd25519PublicKey(base64Key string) (crypto.PrivateKey, error) {
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

	return pkey, nil
}
