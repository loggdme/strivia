package otp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

var (
	// AlphanumericCharacters contains the characters used for alphanumeric OTP codes.
	// Excluding easily misread characters (0, O, 1, I). Using uppercase only.
	AlphanumericCharacters = []rune("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")
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
	Code      string
	ExpiresAt time.Time
	UserID    string
	UserEmail string
}

// GenerateRandomOTP generates a cryptographically secure one-time password based on the provided configuration.
func GenerateRandomOTP(opts GenerateOptsRandomOTP) (*RandomOTPCode, error) {
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

// IsValid checks if the OTP code is still valid.
func (o *RandomOTPCode) IsValid() bool {
	return time.Now().Before(o.ExpiresAt)
}

// String returns a string representation of the OTP code, including its expiration and associated user information.
// $otp$code=<code>,expires=<expiration unix timestamp>,id=<user id>,email=<user email>
func (o *RandomOTPCode) String() string {
	return fmt.Sprintf("$otp$code=%s$expires=%d,id=%s,email=%s", o.Code, o.ExpiresAt.Unix(), o.UserID, o.UserEmail)
}
