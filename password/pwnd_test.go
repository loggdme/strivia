package password

import (
	"crypto/rand"
	"testing"
)

func TestCheckPwnedPasswordSuccess(t *testing.T) {
	password := "password"

	count, err := IsPwnedPassword(password)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	if count <= 0 {
		t.Errorf("Expected a pwned count greater than 0 for '%s', but got %d", password, count)
	}
}

func TestCheckPwnedBytesPasswordSuccess(t *testing.T) {
	password := []byte("password")

	count, err := IsPwnedPassword(password)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	if count <= 0 {
		t.Errorf("Expected a pwned count greater than 0 for '%s', but got %d", password, count)
	}
}

func TestCheckPwnedPasswordNotFound(t *testing.T) {
	password := make([]byte, 32)
	rand.Read(password)

	strPassword := string(password)

	count, err := IsPwnedPassword(strPassword)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	if count != 0 {
		t.Errorf("Expected pwned count 0 for '%s', but got %d", strPassword, count)
	}
}

func TestCheckPwnedBytePasswordNotFound(t *testing.T) {
	password := make([]byte, 32)
	rand.Read(password)

	count, err := IsPwnedPassword(password)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	if count != 0 {
		t.Errorf("Expected pwned count 0 for '%s', but got %d", password, count)
	}
}
