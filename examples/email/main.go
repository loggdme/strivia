package main

import (
	"time"

	strivia_email "github.com/loggdme/strivia/email"
)

func main() {
	emailOtp, _ := strivia_email.GenerateRandomOTP(strivia_email.GenerateOptsRandomOTP{
		Length:   6,
		Validity: 15 * time.Minute,
	})

	emailOtpStr := emailOtp.String()
	println("Random OTP Code:", emailOtpStr)
	println("Random OTP is Valid:", emailOtp.IsValid())

	emailOtpParsed, _ := strivia_email.RandomOTPFromString(emailOtpStr)
	println("Random OTP Parsed:", emailOtpParsed.String())
	println("Random OTP Parsed is Valid:", emailOtpParsed.IsValid())
}
