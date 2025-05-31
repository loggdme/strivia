package otp

import (
	"math"
	"time"

	strivia_random "github.com/loggdme/strivia/random"
)

// TOTPOpts provides options for ValidateCustom().
type TOTPOpts struct {
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint
	// Periods before or after the current time to allow. Value of 1 allows up to Period
	// of either side of the specified time. Defaults to 0 allowed skews.
	Skew uint
	// Digits as part of the input. Defaults to 6.
	Digits Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm Algorithm
}

// GenerateKeyOptsTOTP provides options for .GenerateKeyTOTP()
type GenerateKeyOptsTOTP struct {
	// Name of the issuing Organization/Company.
	Issuer string
	// Name of the User's Account (eg, email address)
	AccountName string
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint
	// Size in size of the generated Secret. Defaults to 20 bytes.
	SecretSize uint32
	// Digits to request. Defaults to 6.
	Digits Digits
	// Algorithm to use for HMAC. Defaults to SHA512.
	Algorithm Algorithm
}

// DefaultParamsTOTP provides secure default parameters for TOTP generation and validation based on the
// RFC 4225 specifications with period=30 seconds, skew=1, digits=6, and algorithm SHA512.
var DefaultParamsTOTP = &TOTPOpts{
	Period:    30,
	Skew:      1,
	Digits:    DigitsSix,
	Algorithm: AlgorithmSHA512,
}

// GenerateCodeTOTP takes a timestamp and produces a passcode using a secret and the
// provided opts. (Under the hood, this is making an adapted call to GenerateHOTP)
func GenerateCodeTOTP(secret string, t time.Time, opts *TOTPOpts) (passcode string, err error) {
	if opts.Period == 0 {
		opts.Period = 30
	}

	counter := uint64(math.Floor(float64(t.Unix()) / float64(opts.Period)))
	passcode, err = GenerateCodeHOTP(secret, counter, HOTPOpts{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
	})

	if err != nil {
		return "", err
	}

	return passcode, nil
}

// VerifyTOTP validates a TOTP given a user specified time and custom options.
func VerifyTOTP(passcode string, secret string, t time.Time, opts *TOTPOpts) (bool, error) {
	if opts.Period == 0 {
		opts.Period = DefaultParamsTOTP.Period
	}

	counters := []uint64{}
	counter := int64(math.Floor(float64(t.Unix()) / float64(opts.Period)))

	counters = append(counters, uint64(counter))
	for i := 1; i <= int(opts.Skew); i++ {
		counters = append(counters, uint64(counter+int64(i)))
		counters = append(counters, uint64(counter-int64(i)))
	}

	for _, counter := range counters {
		rv, err := VerifyHOTP(passcode, counter, secret, HOTPOpts{
			Digits:    opts.Digits,
			Algorithm: opts.Algorithm,
		})

		if err != nil {
			return false, err
		}

		if rv == true {
			return true, nil
		}
	}

	return false, nil
}

// GenerateKeyTOTP creates a new HOTP Key.
func GenerateKeyTOTP(opts GenerateKeyOptsTOTP) (*Key, error) {
	if opts.Issuer == "" {
		return nil, ErrGenerateOtpMissingIssuer
	}

	if opts.AccountName == "" {
		return nil, ErrGenerateOtpMissingAccountName
	}

	if opts.Period == 0 {
		opts.Period = DefaultParamsTOTP.Period
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = 20
	}

	if opts.Digits == 0 {
		opts.Digits = DefaultParamsTOTP.Digits
	}

	return &Key{
		Secret:      strivia_random.SecureRandomBase32String(opts.SecretSize),
		Issuer:      opts.Issuer,
		Period:      opts.Period,
		AccountName: opts.AccountName,
		Algorithm:   opts.Algorithm,
		Digits:      opts.Digits,
		Host:        "totp",
	}, nil
}
