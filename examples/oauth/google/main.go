package main

import (
	"bufio"
	"fmt"
	"os"

	strivia_oauth "github.com/loggdme/strivia/oauth"
	strivia_oauth_providers "github.com/loggdme/strivia/oauth/providers"
)

func main() {
	google := strivia_oauth_providers.NewGoogleProvider("CLIENT_ID", "CLIENT_SECRET", "http://localhost:8080")

	state := strivia_oauth.GenerateRandomState()
	codeVerifier := strivia_oauth.GenerateCodeVerifier()

	authorizationURL := google.CreateAuthorizationURL(state, codeVerifier, []string{"openid", "profile", "email"})
	fmt.Printf("Please open the following URL in your browser:\n%s\n\n", authorizationURL)
	fmt.Printf("Please enter the code you received after authorizing:\n")

	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	code := input.Text()
	fmt.Printf("\n")

	tokens, _ := google.ValidateAuthorizationCode(code, codeVerifier)
	user, _ := google.GetUserFromIdToken(*tokens.IdToken)
	fmt.Printf("%+v\n\n", user)
}
