package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"time"
)

// Digits represents the number of digits present in the
// user's OTP passcode. Six and Eight are the most common values.
type Digits int

// Algorithm represents the hashing function to use in the HMAC
// operation needed for OTPs.
type Algorithm int

const (
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

const (
	AlgorithmSHA512 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA1
	AlgorithmMD5
)

var (
	ErrValidateOtpSecretInvalidBase32 = errors.New("otp: decoding of secret as base32 failed.")
	ErrValidateOtpInputInvalidLength  = errors.New("otp: input length unexpected")
	ErrGenerateOtpMissingIssuer       = errors.New("otp: issuer must be set")
	ErrGenerateOtpMissingAccountName  = errors.New("otp: account_name must be set")
)

// Hash returns a hash.Hash for the given Algorithm.
func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	}

	panic("otp: unknown algorithm")
}

// String returns the string representation of the Algorithm.
func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}

	panic("otp: unknown algorithm")
}

// Format converts an integer into the zero-filled size for this Digits.
func (d Digits) Format(in int32) string {
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", d), in)
}

// Length returns the number of characters for this Digits.
func (d Digits) Length() int {
	return int(d)
}

// String returns the string representation of the digits.
func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}

// Key represents an TOTP or HTOP key.
type Key struct {
	Secret      string
	Issuer      string
	AccountName string
	Host        string
	Period      uint
	Algorithm   Algorithm
	Digits      Digits
}

// NewKey creates a new Key String with the given parameters.
func (k *Key) String() string {
	v := url.Values{}

	v.Set("secret", k.Secret)
	v.Set("issuer", k.Issuer)
	v.Set("algorithm", k.Algorithm.String())
	v.Set("digits", k.Digits.String())

	if k.Period > 0 {
		v.Set("period", strconv.FormatUint(uint64(k.Period), 10))
	}

	u := url.URL{
		Scheme:   "otpauth",
		Host:     k.Host,
		Path:     "/" + k.Issuer + ":" + k.AccountName,
		RawQuery: url.Values.Encode(v),
	}

	return u.String()
}

// Now returns the current time in UTC.
func Now() time.Time {
	return time.Now().UTC()
}
