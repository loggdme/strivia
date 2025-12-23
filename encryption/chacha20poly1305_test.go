package encryption

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestNewEncryptor(t *testing.T) {
	t.Run("valid key size", func(t *testing.T) {
		key := make([]byte, chacha20poly1305.KeySize)
		encryptor, err := NewEncryptor(key)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if encryptor == nil {
			t.Fatal("expected non-nil encryptor")
		}
		if encryptor.aead == nil {
			t.Fatal("expected non-nil aead")
		}
	})

	t.Run("invalid key size - too short", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := NewEncryptor(key)
		if err != ErrInvalidKeySize {
			t.Fatalf("expected ErrInvalidKeySize, got %v", err)
		}
	})

	t.Run("invalid key size - too long", func(t *testing.T) {
		key := make([]byte, 64)
		_, err := NewEncryptor(key)
		if err != ErrInvalidKeySize {
			t.Fatalf("expected ErrInvalidKeySize, got %v", err)
		}
	})

	t.Run("invalid key size - zero length", func(t *testing.T) {
		key := make([]byte, 0)
		_, err := NewEncryptor(key)
		if err != ErrInvalidKeySize {
			t.Fatalf("expected ErrInvalidKeySize, got %v", err)
		}
	})
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	encryptor, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	t.Run("encrypt and decrypt simple text", func(t *testing.T) {
		plaintext := "Hello, World!"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		if ciphertext == "" {
			t.Fatal("expected non-empty ciphertext")
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("expected %q, got %q", plaintext, decrypted)
		}
	})

	t.Run("encrypt empty string", func(t *testing.T) {
		plaintext := ""
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("expected %q, got %q", plaintext, decrypted)
		}
	})

	t.Run("encrypt unicode text", func(t *testing.T) {
		plaintext := "Hello 世界 🌍"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("expected %q, got %q", plaintext, decrypted)
		}
	})

	t.Run("encrypt long text", func(t *testing.T) {
		plaintext := string(make([]byte, 10000))
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if len(decrypted) != len(plaintext) {
			t.Fatalf("expected length %d, got %d", len(plaintext), len(decrypted))
		}
	})

	t.Run("same plaintext produces different ciphertexts", func(t *testing.T) {
		plaintext := "test data"
		ciphertext1, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("first encryption failed: %v", err)
		}

		ciphertext2, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("second encryption failed: %v", err)
		}

		if ciphertext1 == ciphertext2 {
			t.Fatal("expected different ciphertexts for same plaintext due to random nonce")
		}

		// Both should decrypt to the same plaintext
		decrypted1, err := encryptor.Decrypt(ciphertext1)
		if err != nil {
			t.Fatalf("first decryption failed: %v", err)
		}

		decrypted2, err := encryptor.Decrypt(ciphertext2)
		if err != nil {
			t.Fatalf("second decryption failed: %v", err)
		}

		if decrypted1 != plaintext || decrypted2 != plaintext {
			t.Fatal("decryption failed to recover original plaintext")
		}
	})

	t.Run("ciphertext is base64 encoded", func(t *testing.T) {
		plaintext := "test"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Verify it's valid base64
		_, err = base64.StdEncoding.DecodeString(ciphertext)
		if err != nil {
			t.Fatalf("ciphertext is not valid base64: %v", err)
		}
	})
}

func TestDecryptErrors(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	encryptor, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	t.Run("invalid base64", func(t *testing.T) {
		_, err := encryptor.Decrypt("not-valid-base64!!!")
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})

	t.Run("ciphertext too short", func(t *testing.T) {
		// Create a base64 encoded string that's shorter than nonce size
		shortData := make([]byte, encryptor.aead.NonceSize()-1)
		encoded := base64.StdEncoding.EncodeToString(shortData)

		_, err := encryptor.Decrypt(encoded)
		if err != ErrCiphertextTooShort {
			t.Fatalf("expected ErrCiphertextTooShort, got %v", err)
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		plaintext := "secret message"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Decode, tamper, re-encode
		decoded, _ := base64.StdEncoding.DecodeString(ciphertext)
		if len(decoded) > 0 {
			decoded[len(decoded)-1] ^= 0xFF // Flip last byte
		}
		tampered := base64.StdEncoding.EncodeToString(decoded)

		_, err = encryptor.Decrypt(tampered)
		if err != ErrDecryptionFailed {
			t.Fatalf("expected ErrDecryptionFailed, got %v", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		// Encrypt with one key
		plaintext := "secret"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Try to decrypt with different key
		differentKey, err := GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate different key: %v", err)
		}

		differentEncryptor, err := NewEncryptor(differentKey)
		if err != nil {
			t.Fatalf("failed to create different encryptor: %v", err)
		}

		_, err = differentEncryptor.Decrypt(ciphertext)
		if err != ErrDecryptionFailed {
			t.Fatalf("expected ErrDecryptionFailed, got %v", err)
		}
	})
}

func TestGenerateKey(t *testing.T) {
	t.Run("generates correct size", func(t *testing.T) {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		if len(key) != chacha20poly1305.KeySize {
			t.Fatalf("expected key size %d, got %d", chacha20poly1305.KeySize, len(key))
		}
	})

	t.Run("generates different keys", func(t *testing.T) {
		key1, err := GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate first key: %v", err)
		}

		key2, err := GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate second key: %v", err)
		}

		if string(key1) == string(key2) {
			t.Fatal("expected different keys, got identical keys")
		}
	})

	t.Run("generated key works with encryptor", func(t *testing.T) {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		encryptor, err := NewEncryptor(key)
		if err != nil {
			t.Fatalf("failed to create encryptor with generated key: %v", err)
		}

		plaintext := "test"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("expected %q, got %q", plaintext, decrypted)
		}
	})
}

func TestEncodeDecodeKey(t *testing.T) {
	t.Run("round trip encoding", func(t *testing.T) {
		originalKey, err := GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		encoded := EncodeKey(originalKey)
		if encoded == "" {
			t.Fatal("expected non-empty encoded key")
		}

		decoded, err := DecodeKey(encoded)
		if err != nil {
			t.Fatalf("failed to decode key: %v", err)
		}

		if string(decoded) != string(originalKey) {
			t.Fatal("decoded key does not match original key")
		}
	})

	t.Run("encoded key is valid base64", func(t *testing.T) {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		encoded := EncodeKey(key)

		// Verify it's valid base64
		_, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("encoded key is not valid base64: %v", err)
		}
	})

	t.Run("decode invalid base64", func(t *testing.T) {
		_, err := DecodeKey("not-valid-base64!!!")
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})

	t.Run("decode wrong size key", func(t *testing.T) {
		wrongSizeKey := make([]byte, 16)
		encoded := base64.StdEncoding.EncodeToString(wrongSizeKey)

		_, err := DecodeKey(encoded)
		if err != ErrInvalidKeySize {
			t.Fatalf("expected ErrInvalidKeySize, got %v", err)
		}
	})

	t.Run("decoded key works with encryptor", func(t *testing.T) {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		encoded := EncodeKey(key)
		decoded, err := DecodeKey(encoded)
		if err != nil {
			t.Fatalf("failed to decode key: %v", err)
		}

		encryptor, err := NewEncryptor(decoded)
		if err != nil {
			t.Fatalf("failed to create encryptor with decoded key: %v", err)
		}

		plaintext := "test message"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("expected %q, got %q", plaintext, decrypted)
		}
	})
}

func TestEncryptionCrossTalk(t *testing.T) {
	t.Run("multiple encryptors with same key", func(t *testing.T) {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		encryptor1, err := NewEncryptor(key)
		if err != nil {
			t.Fatalf("failed to create first encryptor: %v", err)
		}

		encryptor2, err := NewEncryptor(key)
		if err != nil {
			t.Fatalf("failed to create second encryptor: %v", err)
		}

		plaintext := "shared secret"

		// Encrypt with first encryptor
		ciphertext, err := encryptor1.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Decrypt with second encryptor
		decrypted, err := encryptor2.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("expected %q, got %q", plaintext, decrypted)
		}
	})
}
