package main

import (
	strivia_otp "github.com/loggdme/strivia/otp"
)

func main() {
	key, _ := strivia_otp.GenerateKeyTOTP(strivia_otp.GenerateKeyOptsTOTP{
		Issuer:      "loggd.me",
		AccountName: "tobias@loggd.me",
	})

	passcode, _ := strivia_otp.GenerateCodeTOTP(key.Secret, strivia_otp.Now(), strivia_otp.DefaultParamsTOTP)
	isValid, _ := strivia_otp.VerifyTOTP(passcode, key.Secret, strivia_otp.Now(), strivia_otp.DefaultParamsTOTP)

	println("Key:", key.String())
	println("Passcode:", passcode)
	println("Code is valid:", isValid)

	emailOtp, _ := strivia_otp.GenerateRandomOTP(strivia_otp.GenerateOptsRandomOTP{
		UserID:    "12345",
		UserEmail: "tobias@loggd.me",
	})

	println("Random OTP Code:", emailOtp.String())
	println("Random OTP is Valid:", emailOtp.IsValid())
}
