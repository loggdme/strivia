package main

import (
	"fmt"
	"time"

	"github.com/loggdme/strivia/jwt"
	"github.com/loggdme/strivia/random"
)

type CustomClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func main() {
	privateKeyStr := "MC4CAQAwBQYDK2VwBCIEIJ7VP4bGde7HFmugf7wnZ+f09S4wXiHTPqCQB/HYLw+s"
	// publicKeyStr := "MCowBQYDK2VwAyEA7rD1JBNE9qhzXQBN3mltLsAQy34dwDljiSPzmYeqiiM="

	newToken := jwt.NewToken(&CustomClaims{
		Email: "user_new@loggd.me",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "loggd.me",
			Subject:   "unique-user-id",
			Audience:  []string{"loggd.me"},
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(time.Hour * 24)},
			IssuedAt:  &jwt.NumericDate{Time: time.Now()},
			NotBefore: &jwt.NumericDate{Time: time.Now()},
			ID:        random.SecureRandomBase32String(32),
		},
	})

	privateKey, _ := jwt.ParseEd25519PrivateKey(privateKeyStr)
	signedToken, _ := newToken.SignedString(privateKey)
	fmt.Printf("Signed Token: %s\n", signedToken)
}
