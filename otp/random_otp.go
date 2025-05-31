package otp

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	// AlphanumericCharacters contains the characters used for alphanumeric OTP codes.
	// Excluding easily misread characters (0, O, 1, I). Using uppercase only.
	AlphanumericCharacters = []rune("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")
)

var (
	// ErrParseRandomOtpFromStringFormat indicates that the provided string format is invalid.
	ErrParseRandomOtpFromStringFormat = errors.New("otp: invalid random OTP format")
	// ErrParseRandomOtpFromStringValues indicates that the provided string does not contain valid values.
	ErrParseRandomOtpFromStringValues = errors.New("otp: invalid random OTP values")
	// ErrGenerateRandomOtpMissingUserEmail indicates that the user email is required but not provided.
	ErrGenerateRandomOtpMissingUserEmail = errors.New("otp: user_email must be set")
	// ErrGenerateRandomOtpMissingUserID indicates that the user ID is required but not provided.
	ErrGenerateRandomOtpMissingUserID = errors.New("otp: user_id must be set")
)

// GenerateOptsRandomOTP holds the configuration for generating an OTP code.
type GenerateOptsRandomOTP struct {
	// Length specifies the desired length of the OTP code. Defaults to 6.
	Length int
	// Validity specifies the duration the OTP code should be valid for. Defaults to 15 minutes.
	Validity time.Duration
	// UserID is used to tie the code to a specific user.
	UserID string
	// UserEmail is used to associate the OTP code with a user's email.
	UserEmail string
}

// RandomOTPCode represents an generated OTP code with its associated data.
type RandomOTPCode struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    string    `json:"user_id"`
	UserEmail string    `json:"user_email"`
}

// GenerateRandomOTP generates a cryptographically secure one-time password based on the provided configuration.
func GenerateRandomOTP(opts GenerateOptsRandomOTP) (*RandomOTPCode, error) {
	if opts.UserEmail == "" {
		return nil, ErrGenerateRandomOtpMissingUserEmail
	}

	if opts.UserID == "" {
		return nil, ErrGenerateRandomOtpMissingUserID
	}

	if opts.Length <= 0 {
		opts.Length = 6
	}

	if opts.Validity <= 0 {
		opts.Validity = 15 * time.Minute
	}

	code := make([]rune, opts.Length)
	max := uint32(len(AlphanumericCharacters))

	for i := range code {
		bytes := make([]byte, 4)
		rand.Read(bytes)
		randomIndex := binary.BigEndian.Uint32(bytes) % max
		code[i] = AlphanumericCharacters[randomIndex]
	}

	return &RandomOTPCode{
		Code:      string(code),
		ExpiresAt: time.Now().Add(opts.Validity),
		UserID:    opts.UserID,
		UserEmail: opts.UserEmail,
	}, nil
}

// RandomOTPFromString parses a json representation of a random OTP code and returns a RandomOTPCode instance.
// Returns an error if the string cannot be parsed correctly.
func RandomOTPFromString(s string) (*RandomOTPCode, error) {
	var data RandomOTPCode
	if err := json.Unmarshal([]byte(s), &data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseRandomOtpFromStringFormat, err)
	}

	if data.Code == "" || data.UserID == "" || data.UserEmail == "" || data.ExpiresAt.IsZero() {
		return nil, ErrParseRandomOtpFromStringValues
	}

	return &RandomOTPCode{
		Code:      data.Code,
		ExpiresAt: data.ExpiresAt,
		UserID:    data.UserID,
		UserEmail: data.UserEmail,
	}, nil
}

// IsValid checks if the OTP code is still valid.
func (o *RandomOTPCode) IsValid() bool {
	return time.Now().Before(o.ExpiresAt)
}

// String returns a json representation of the OTP code, including its expiration and associated user information.
func (o *RandomOTPCode) String() string {
	data, _ := json.Marshal(o)
	return string(data)
}
