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
	privateKeyStr := "MC4CAQAwBQYDK2VwBCIEIBNHmOiDd/gS4XOKxzBA+yLQ+9i9eFH50y1CfNYW8u2e"
	publicKeyStr := "MCowBQYDK2VwAyEAIcjUkocF8Vxw6BcY3c8nx1DjgXcCLlqwFfLkma+uJr4="

	newToken := jwt.NewToken(&CustomClaims{
		Email: "user@loggd.me",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "loggd.me",
			Subject:   "unique-user-id",
			Audience:  []string{"loggd.me"},
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(time.Hour * 24 * 365)},
			IssuedAt:  &jwt.NumericDate{Time: time.Now()},
			NotBefore: &jwt.NumericDate{Time: time.Now()},
			ID:        random.SecureRandomBase32String(32),
		},
	})

	privateKey, _ := jwt.ParseEd25519PrivateKey(privateKeyStr)
	publicKey, _ := jwt.ParseEd25519PublicKey(publicKeyStr)

	signedToken, _ := newToken.SignedString(&privateKey)
	fmt.Printf("Signed Token: %s\n\n", signedToken)

	expectedClaims := jwt.ExpectedClaims{
		Issuer:   "loggd.me",
		Audience: []string{"loggd.me"},
	}

	parsedToken, _ := jwt.VerifyToken[CustomClaims](signedToken, &publicKey, &expectedClaims)
	fmt.Printf("Token Claims: %+v\n\n", parsedToken.Claims)
}
