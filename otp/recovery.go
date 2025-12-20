package otp

import strivia_random "github.com/loggdme/strivia/random"

func GenerateRecoveryCode(length int) string {
	return strivia_random.SecureRandomBase32String(uint32(length))
}

func GenerateRecoveryCodes(count int) []string {
	codes := make([]string, count)
	for i := range codes {
		codes[i] = GenerateRecoveryCode(16)
	}
	return codes
}
