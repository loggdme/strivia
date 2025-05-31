package main

import (
	"crypto/rand"
	"fmt"

	strivia_password "github.com/loggdme/strivia/password"
)

func main() {
	// Check if common used password is pwned
	weakPassword := "P@ssw0rd"

	weakPwned, _ := strivia_password.IsPwnedPassword(weakPassword)
	fmt.Printf("Weak password was pwned %d times\n", weakPwned)

	// Create a strong and random password
	strongPassword := make([]byte, 32)
	rand.Read(strongPassword)

	strongPwned, _ := strivia_password.IsPwnedPassword(strongPassword)
	fmt.Printf("Strong password was pwned %d times\n", strongPwned)
}
