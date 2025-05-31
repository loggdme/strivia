package main

import (
	"fmt"

	strivia_hashing "github.com/loggdme/strivia/hashing"
)

func main() {
	plainPassword := "P@ssw0rd"

	// Create a password hash
	hash := strivia_hashing.CreateHash(plainPassword, strivia_hashing.DefaultParamsRFC1)
	fmt.Printf("Password Hash: %s\n", hash)

	// Check if the password is valid
	match, _ := strivia_hashing.ComparePasswordAndHash(plainPassword, hash)
	fmt.Printf("Password is valid: %v\n", match)
}
