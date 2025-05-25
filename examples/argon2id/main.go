package main

import (
	"fmt"

	"github.com/loggdme/strivia"
)

func main() {
	plainPassword := "P@ssw0rd"

	// Create a password hash
	hash := strivia.CreateHash(plainPassword, strivia.DefaultParamsRFC1)
	fmt.Printf("Password Hash: %s\n", hash)

	// Check if the password is valid
	match, _ := strivia.ComparePasswordAndHash(plainPassword, hash)
	fmt.Printf("Password is valid: %v\n", match)
}
