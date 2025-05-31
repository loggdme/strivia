package random

import (
	"encoding/base32"
	"math/big"
	"testing"
)

/* Benchmarks */

func BenchmarkSecureRandomFloat64(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = SecureRandomFloat64()
	}
}

func BenchmarkSecureSecureRandomUint64(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = SecureRandomUint64(big.NewInt(10))
	}
}

func BenchmarkSecureRandomBase32String(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = SecureRandomBase32String(16)
	}
}

/* Tests */

func TestSecureRandomBase32String_Length(t *testing.T) {
	for _, length := range []uint32{1, 5, 10, 20, 50} {
		str := SecureRandomBase32String(length)
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(str)
		if err != nil {
			t.Fatalf("Failed to decode base32 string: %v", err)
		}
		if uint32(len(decoded)) != length {
			t.Errorf("Expected decoded length %d, got %d", length, len(decoded))
		}
	}
}

func TestSecureRandomBase32String_Uniqueness(t *testing.T) {
	str1 := SecureRandomBase32String(16)
	str2 := SecureRandomBase32String(16)
	if str1 == str2 {
		t.Errorf("Expected different random strings, got identical: %s", str1)
	}
}

func TestSecureRandomBase32String_PanicOnZeroOrNegativeLength(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for zero or negative length, but did not panic")
		}
	}()
	SecureRandomBase32String(0)
}

func TestSecureRandomChoice_SelectsElement(t *testing.T) {
	ints := []int{10, 20, 30, 40, 50}
	seen := make(map[int]bool)

	for range 100 {
		val := SecureRandomChoice(&ints)
		if val == nil {
			t.Fatal("Expected non-nil pointer from SecureRandomChoice")
		}
		seen[*val] = true
	}

	if len(seen) != len(ints) {
		t.Errorf("Expected to see all elements, saw: %v", seen)
	}
}

func TestSecureRandomChoice_PointerIdentity(t *testing.T) {
	strs := []string{"a", "b", "c"}
	ptr := SecureRandomChoice(&strs)
	found := false

	for i := range strs {
		if ptr == &strs[i] {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Returned pointer does not match any element in the slice")
	}
}

func TestSecureRandomChoice_PanicOnEmptySlice(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for empty slice, but did not panic")
		}
	}()
	empty := []int{}
	SecureRandomChoice(&empty)
}

func TestSecureRandomBytes_Length(t *testing.T) {
	for _, length := range []uint32{1, 8, 16, 32, 64} {
		bytes := SecureRandomBytes(length)
		if uint32(len(bytes)) != length {
			t.Errorf("Expected length %d, got %d", length, len(bytes))
		}
	}
}

func TestSecureRandomBytes_Uniqueness(t *testing.T) {
	b1 := SecureRandomBytes(16)
	b2 := SecureRandomBytes(16)
	if string(b1) == string(b2) {
		t.Errorf("Expected different random byte slices, got identical: %v", b1)
	}
}

func TestSecureRandomBytes_PanicOnZeroOrNegativeLength(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for zero or negative length, but did not panic")
		}
	}()
	SecureRandomBytes(0)
}

func TestSecureRandomUint64_Range(t *testing.T) {
	tests := []uint64{1, 2, 10, 100, 1 << 16, 1 << 32, 1<<63 - 1}

	for _, max := range tests {
		bigMax := big.NewInt(int64(max))
		for range 100 {
			val := SecureRandomUint64(bigMax)
			if val >= max {
				t.Errorf("Value %d is not less than max %d", val, max)
			}
		}
	}
}

func TestSecureRandomUint64_Uniqueness(t *testing.T) {
	max := big.NewInt(1 << 32)
	vals := make(map[uint64]struct{})

	for range 100 {
		val := SecureRandomUint64(max)
		vals[val] = struct{}{}
	}

	if len(vals) < 90 {
		t.Errorf("Expected at least 90 unique values, got %d", len(vals))
	}
}

func TestSecureRandomUint64_PanicOnNonPositiveMax(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for non-positive max, but did not panic")
		}
	}()
	SecureRandomUint64(big.NewInt(0))
}

func TestSecureRandomFloat64_Range(t *testing.T) {
	for range 1000 {
		val := SecureRandomFloat64()
		if val < 0.0 || val >= 1.0 {
			t.Errorf("SecureRandomFloat64() = %v, want in [0, 1)", val)
		}
	}
}

func TestSecureRandomFloat64_Uniqueness(t *testing.T) {
	vals := make(map[float64]struct{})
	for range 100 {
		val := SecureRandomFloat64()
		vals[val] = struct{}{}
	}
	if len(vals) < 90 {
		t.Errorf("Expected at least 90 unique values, got %d", len(vals))
	}
}
