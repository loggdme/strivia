package otp

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"math"
	"strings"

	strivia_random "github.com/loggdme/strivia/random"
)

// HOTPOpts provides options for ValidateCustom().
type HOTPOpts struct {
	// Digits as part of the input. Defaults to 6.
	Digits Digits
	// Algorithm to use for HMAC. Defaults to SHA512.
	Algorithm Algorithm
}

// GenerateKeyOptsHOTP provides options for .GenerateKeyHOTP()
type GenerateKeyOptsHOTP struct {
	// Name of the issuing Organization/Company.
	Issuer string
	// Name of the User's Account (eg, email address)
	AccountName string
	// Size in size of the generated Secret. Defaults to 10 bytes.
	SecretSize uint32
	// Digits to request. Defaults to 6.
	Digits Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm Algorithm
}

// DefaultParamsHOTP provides secure default parameters for TOTP generation and validation based on the
// RFC 4225 specifications with digits=6, and algorithm SHA512.
var DefaultParamsHOTP = &HOTPOpts{
	Digits:    DigitsSix,
	Algorithm: AlgorithmSHA512,
}

// GenerateCodeHOTP uses a counter and secret value and options struct to
// create a passcode.
func GenerateCodeHOTP(secret string, counter uint64, opts HOTPOpts) (passcode string, err error) {
	if opts.Digits == 0 {
		opts.Digits = DigitsSix
	}

	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret = secret + strings.Repeat("=", 8-n)
	}
	secret = strings.ToUpper(secret)

	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", ErrValidateSecretInvalidBase32
	}

	buf := make([]byte, 8)
	mac := hmac.New(opts.Algorithm.Hash, secretBytes)
	binary.BigEndian.PutUint64(buf, counter)

	mac.Write(buf)
	sum := mac.Sum(nil)

	// "Dynamic truncation" in RFC 4226 http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	l := opts.Digits.Length()

	mod := int32(value % int64(math.Pow10(l)))
	passcode = opts.Digits.Format(mod)
	return passcode, nil
}

// VerifyHOTP validates an HOTP with customizable options.
func VerifyHOTP(passcode string, counter uint64, secret string, opts HOTPOpts) (bool, error) {
	passcode = strings.TrimSpace(passcode)

	if len(passcode) != opts.Digits.Length() {
		return false, ErrValidateInputInvalidLength
	}

	otpStr, err := GenerateCodeHOTP(secret, counter, opts)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(otpStr), []byte(passcode)) == 1 {
		return true, nil
	}

	return false, nil
}

// GenerateKeyHOTP creates a new HOTP Key.
func GenerateKeyHOTP(opts GenerateKeyOptsHOTP) (*Key, error) {
	if opts.Issuer == "" {
		return nil, ErrGenerateMissingIssuer
	}

	if opts.AccountName == "" {
		return nil, ErrGenerateMissingAccountName
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = 10
	}

	if opts.Digits == 0 {
		opts.Digits = DigitsSix
	}

	return &Key{
		Secret:      strivia_random.SecureRandomBase32String(opts.SecretSize),
		Issuer:      opts.Issuer,
		AccountName: opts.AccountName,
		Algorithm:   opts.Algorithm,
		Digits:      opts.Digits,
		Host:        "hotp",
	}, nil
}
