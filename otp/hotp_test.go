package otp

import (
	"encoding/base32"
	"testing"
)

type tcHOTP struct {
	Counter uint64
	TOTP    string
	Mode    Algorithm
	Secret  string
}

var (
	secSha1HOTP = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	rfcMatrixTCsHOTP = []tcHOTP{
		{0, "755224", AlgorithmSHA1, secSha1HOTP},
		{1, "287082", AlgorithmSHA1, secSha1HOTP},
		{2, "359152", AlgorithmSHA1, secSha1HOTP},
		{3, "969429", AlgorithmSHA1, secSha1HOTP},
		{4, "338314", AlgorithmSHA1, secSha1HOTP},
		{5, "254676", AlgorithmSHA1, secSha1HOTP},
		{6, "287922", AlgorithmSHA1, secSha1HOTP},
		{7, "162583", AlgorithmSHA1, secSha1HOTP},
		{8, "399871", AlgorithmSHA1, secSha1HOTP},
		{9, "520489", AlgorithmSHA1, secSha1HOTP},
	}
)

func TestVerifyHOTP_RFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCsHOTP {
		valid, err := VerifyHOTP(tx.TOTP, tx.Counter, tx.Secret,
			HOTPOpts{
				Digits:    DigitsSix,
				Algorithm: tx.Mode,
			})
		if err != nil {
			t.Errorf("unexpected error totp=%s mode=%v counter=%v: %v", tx.TOTP, tx.Mode, tx.Counter, err)
		}
		if !valid {
			t.Errorf("unexpected totp failure totp=%s mode=%v counter=%v", tx.TOTP, tx.Mode, tx.Counter)
		}
	}
}

func TestGenerateCodeHOTP_RFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCsHOTP {
		passcode, err := GenerateCodeHOTP(tx.Secret, tx.Counter,
			HOTPOpts{
				Digits:    DigitsSix,
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

func TestGenerateCodeHOTP(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	code, err := GenerateCodeHOTP("foo", 1, HOTPOpts{})

	if err != ErrValidateOtpSecretInvalidBase32 {
		t.Errorf("Decoding of secret as base32 failed. Expected %v, got %v", ErrValidateOtpSecretInvalidBase32, err)
	}

	if code != "" {
		t.Errorf("Code should be empty string when we have an error. Expected \"\", got %s", code)
	}

	code, err = GenerateCodeHOTP(secSha1, 1, HOTPOpts{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(code) != 6 {
		t.Errorf("Code should be 6 digits when we have not an error. Expected 6, got %d", len(code))
	}
}

func TestVerifyHOTPInvalid(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	valid, err := VerifyHOTP("foo", 11, secSha1,
		HOTPOpts{
			Digits:    DigitsSix,
			Algorithm: AlgorithmSHA1,
		})
	if err != ErrValidateOtpInputInvalidLength {
		t.Errorf("Expected Invalid length error. Expected %v, got %v", ErrValidateOtpInputInvalidLength, err)
	}
	if valid != false {
		t.Errorf("Valid should be false when we have an error. Expected false, got %t", valid)
	}

	valid, err = VerifyHOTP("foo", 11, secSha1,
		HOTPOpts{
			Digits:    DigitsEight,
			Algorithm: AlgorithmSHA1,
		})
	if err != ErrValidateOtpInputInvalidLength {
		t.Errorf("Expected Invalid length error. Expected %v, got %v", ErrValidateOtpInputInvalidLength, err)
	}
	if valid != false {
		t.Errorf("Valid should be false when we have an error. Expected false, got %t", valid)
	}

	valid, err = VerifyHOTP("000000", 11, secSha1,
		HOTPOpts{
			Digits:    DigitsSix,
			Algorithm: AlgorithmSHA1,
		})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if valid != false {
		t.Errorf("Valid should be false. Expected false, got %t", valid)
	}

	valid, _ = VerifyHOTP("000000", 11, secSha1, HOTPOpts{})
	if valid != false {
		t.Errorf("Valid should be false. Expected false, got %t", valid)
	}
}

func TestValidatePadding(t *testing.T) {
	valid, err := VerifyHOTP("831097", 0, "JBSWY3DPEHPK3PX",
		HOTPOpts{
			Digits:    DigitsSix,
			Algorithm: AlgorithmSHA1,
		})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if valid != true {
		t.Errorf("Valid should be true. Expected true, got %t", valid)
	}
}

func TestValidateLowerCaseSecret(t *testing.T) {
	valid, err := VerifyHOTP("831097", 0, "jbswy3dpehpk3px",
		HOTPOpts{
			Digits:    DigitsSix,
			Algorithm: AlgorithmSHA1,
		})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if valid != true {
		t.Errorf("Valid should be true. Expected true, got %t", valid)
	}
}
