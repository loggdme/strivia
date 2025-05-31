package otp

import (
	"encoding/base32"
	"testing"
	"time"
)

type tcTOTP struct {
	TS     int64
	TOTP   string
	Mode   Algorithm
	Secret string
}

var (
	secSha1TOTP   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256TOTP = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512TOTP = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcMatrixTCsTOTP = []tcTOTP{
		{59, "94287082", AlgorithmSHA1, secSha1TOTP},
		{59, "46119246", AlgorithmSHA256, secSha256TOTP},
		{59, "90693936", AlgorithmSHA512, secSha512TOTP},
		{1111111109, "07081804", AlgorithmSHA1, secSha1TOTP},
		{1111111109, "68084774", AlgorithmSHA256, secSha256TOTP},
		{1111111109, "25091201", AlgorithmSHA512, secSha512TOTP},
		{1111111111, "14050471", AlgorithmSHA1, secSha1TOTP},
		{1111111111, "67062674", AlgorithmSHA256, secSha256TOTP},
		{1111111111, "99943326", AlgorithmSHA512, secSha512TOTP},
		{1234567890, "89005924", AlgorithmSHA1, secSha1TOTP},
		{1234567890, "91819424", AlgorithmSHA256, secSha256TOTP},
		{1234567890, "93441116", AlgorithmSHA512, secSha512TOTP},
		{2000000000, "69279037", AlgorithmSHA1, secSha1TOTP},
		{2000000000, "90698825", AlgorithmSHA256, secSha256TOTP},
		{2000000000, "38618901", AlgorithmSHA512, secSha512TOTP},
		{20000000000, "65353130", AlgorithmSHA1, secSha1TOTP},
		{20000000000, "77737706", AlgorithmSHA256, secSha256TOTP},
		{20000000000, "47863826", AlgorithmSHA512, secSha512TOTP},
	}
)

func TestVerifyTOTP_RFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCsTOTP {
		valid, err := VerifyTOTP(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			&TOTPOpts{
				Digits:    DigitsEight,
				Algorithm: tx.Mode,
				Skew:      1,
			})
		if err != nil {
			t.Errorf("unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		}
		if !valid {
			t.Errorf("unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		}
	}
}

func TestGenerateCodeTOTP_RFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCsTOTP {
		passcode, err := GenerateCodeTOTP(tx.Secret, time.Unix(tx.TS, 0).UTC(),
			&TOTPOpts{
				Digits:    DigitsEight,
				Algorithm: tx.Mode,
			})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if passcode != tx.TOTP {
			t.Errorf("expected %s, got %s", tx.TOTP, passcode)
		}
	}
}

func TestVerifyTOTPSkew(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	tests := []tcTOTP{
		{29, "94287082", AlgorithmSHA1, secSha1},
		{59, "94287082", AlgorithmSHA1, secSha1},
		{61, "94287082", AlgorithmSHA1, secSha1},
	}

	for _, tx := range tests {
		valid, err := VerifyTOTP(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			&TOTPOpts{
				Digits:    DigitsEight,
				Algorithm: tx.Mode,
				Skew:      1,
			})

		if err != nil {
			t.Errorf("unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		}

		if !valid {
			t.Errorf("unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		}
	}
}
