package otp

import (
	"github.com/loggdme/strivia/hashing"
	strivia_random "github.com/loggdme/strivia/random"
)

const (
	RecoveryCodeLength = 16
)

func GenerateRecoveryCode(length uint32) string {
	return strivia_random.SecureRandomBase32StringExactLength(length)
}

func GenerateRecoveryCodes(count int) []string {
	codes := make([]string, count)
	for i := range codes {
		codes[i] = GenerateRecoveryCode(RecoveryCodeLength)
	}
	return codes
}

func HashRecoveryCode(code string) string {
	return hashing.CreateHash(code, hashing.DefaultParamsOWASP)
}

func HashRecoveryCodes(codes []string) []string {
	hashedCodes := make([]string, len(codes))
	for i := range codes {
		hashedCodes[i] = HashRecoveryCode(codes[i])
	}
	return hashedCodes
}

func VerifyRecoveryCode(code string, hash string) bool {
	match, err := hashing.ComparePasswordAndHash(code, hash)
	return match && err == nil
}
