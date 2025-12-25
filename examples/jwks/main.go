package main

import (
	"fmt"

	"github.com/loggdme/strivia/jwt"
)

func main() {
	jwks, err := jwt.FetchJWKS("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		panic(err)
	}

	fmt.Println("Available keys:")
	for _, key := range jwks.Keys {
		fmt.Printf("  - Kid: %s, Alg: %s\n", key.Kid, key.Alg)
	}
	fmt.Println()

	targetKid := "6a906ec119d7ba46a6a43ef1ea842e34a8ee08b4"

	jwk, err := jwks.FindKeyByKid(targetKid)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	pubKey, err := jwk.ToRSAPublicKey()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Found key with Kid: %s\n", targetKid)
	fmt.Printf("Algorithm: %s\n", jwk.Alg)
	fmt.Printf("Use: %s\n", jwk.Use)
	fmt.Printf("RSA Public Key Modulus size: %d bits\n", pubKey.N.BitLen())
	fmt.Printf("RSA Public Key Exponent: %d\n", pubKey.E)
}
