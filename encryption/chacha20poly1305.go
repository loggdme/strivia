package encryption

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidKeySize     = errors.New("key must be 32 bytes for ChaCha20-Poly1305")
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	ErrDecryptionFailed   = errors.New("decryption failed: authentication tag mismatch")
)

// Encryptor handles encryption and decryption of sensitive data using ChaCha20-Poly1305
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor creates a new Encryptor instance with the provided 32-byte key
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKeySize
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &Encryptor{aead: aead}, nil
}

// Encrypt encrypts the plaintext and returns a base64-encoded string
// The nonce is prepended to the ciphertext automatically
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, e.aead.NonceSize(), e.aead.NonceSize()+len(plaintext)+e.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := e.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext and returns the plaintext
func (e *Encryptor) Decrypt(encoded string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	nonceSize := e.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrCiphertextTooShort
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}

// GenerateKey generates a cryptographically secure random 32-byte key
// This should be called once and the key stored securely (e.g., environment variable, secret manager)
func GenerateKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncodeKey encodes a key to base64 for storage in environment variables
func EncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// DecodeKey decodes a base64-encoded key from environment variables
func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKeySize
	}
	return key, nil
}
