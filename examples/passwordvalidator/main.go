package main

import (
	"fmt"

	strivia_password "github.com/loggdme/strivia/password"
)

func main() {
	const minEntropyBits = 60

	fmt.Printf("Entropy: %f bits\n", strivia_password.GetPasswordEntropy("12345678"))
	isValid := strivia_password.ValidatePasswordStrength("Simpsons1309!", minEntropyBits)

	fmt.Printf("Password is valid: %t\n", isValid)
}
