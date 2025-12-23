package random

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"math"
	"math/big"
)

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// SecureRandomBase32String generates a cryptographically secure random base32 string of the specified length.
// NOTE: The length is the length of the random bytes which are encoded. The string will be longer.
func SecureRandomBase32String(length uint32) string {
	return b32NoPadding.EncodeToString(SecureRandomBytes(length))
}

// SecureRandomBase32StringExactLength generates a cryptographically secure random base32 string of the exact specified length.
func SecureRandomBase32StringExactLength(length uint32) string {
	return SecureRandomBase32String(length)[:length]
}

// SecureRandomChoice selects a random item from a slice of items using a cryptographically secure method.
// It returns a pointer to the selected item.
// The slice must not be empty. If it is, the function will panic.
func SecureRandomChoice[T any](items *[]T) *T {
	if len(*items) == 0 {
		panic("random: slice must not be empty")
	}

	return &(*items)[SecureRandomUint64(big.NewInt(int64(len(*items))))]
}

// SecureRandomBytes generates a slice of cryptographically secure random bytes of the specified length.
// It uses the crypto/rand package to ensure the randomness is suitable for security-sensitive applications.
// The length must be a positive integer. If it is not, the function will panic.
func SecureRandomBytes(length uint32) []byte {
	if length <= 0 {
		panic("random: length must be a positive integer")
	}

	bytes := make([]byte, length)
	rand.Read(bytes)
	return bytes
}

// SecureRandomUint64 generates a cryptographically secure random uint64 value in the range [0, max).
// The max parameter must be a positive *big.Int. The function uses crypto/rand to generate random bytes,
// masks the most significant bits if necessary to ensure the value is less than max, and repeats the process
// until a suitable value is found. The returned value is always less than max.
func SecureRandomUint64(max *big.Int) uint64 {
	if max.Cmp(big.NewInt(0)) <= 0 {
		panic("random: max must be a positive *big.Int")
	}

	randVal := new(big.Int)
	shift := max.BitLen() % 8
	bytes := make([]byte, (max.BitLen()/8)+1)
	rand.Read(bytes)

	if shift != 0 {
		bytes[0] &= (1 << shift) - 1
	}

	randVal.SetBytes(bytes)
	for randVal.Cmp(max) >= 0 {
		rand.Read(bytes)
		if shift != 0 {
			bytes[0] &= (1 << shift) - 1
		}
		randVal.SetBytes(bytes)
	}

	return randVal.Uint64()
}

// SecureRandomFloat64 generates a cryptographically secure random float64 value in the range [0, 1).
// It constructs a random 64-bit IEEE 754 floating-point number by generating random bytes,
// setting the exponent bits to represent 1.x, and then subtracting 1 to ensure the result is in [0, 1).
// This function uses crypto/rand for secure random number generation.
func SecureRandomFloat64() float64 {
	bytes := make([]byte, 7)
	rand.Read(bytes)

	bytes = append(make([]byte, 1), bytes...)
	bytes[0] = 0x3f
	bytes[1] |= 0xf0

	return math.Float64frombits(binary.BigEndian.Uint64(bytes)) - 1
}
