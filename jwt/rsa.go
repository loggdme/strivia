package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

var (
	ErrRSAVerification = errors.New("jwt-rsa: verification error")
)

type SigningMethodRSA struct {
	Name string
	Hash crypto.Hash
}

var (
	SigningMethodRS256 *SigningMethodRSA
	SigningMethodRS384 *SigningMethodRSA
	SigningMethodRS512 *SigningMethodRSA
)

func init() {
	SigningMethodRS256 = &SigningMethodRSA{"RS256", crypto.SHA256}
	SigningMethodRS384 = &SigningMethodRSA{"RS384", crypto.SHA384}
	SigningMethodRS512 = &SigningMethodRSA{"RS512", crypto.SHA512}
}

func (m *SigningMethodRSA) Alg() string {
	return m.Name
}

func (m *SigningMethodRSA) VerifyRSA(signingString string, sig []byte, key *rsa.PublicKey) error {
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	if err := rsa.VerifyPKCS1v15(key, m.Hash, hasher.Sum(nil), sig); err != nil {
		return ErrRSAVerification
	}

	return nil
}

func (m *SigningMethodRSA) SignRSA(signingString string, key *rsa.PrivateKey) ([]byte, error) {
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, m.Hash, hasher.Sum(nil))
	if err != nil {
		return nil, ErrRSAVerification
	}

	return sig, nil
}
