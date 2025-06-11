package main

import (
	"bufio"
	"fmt"
	"os"

	strivia_oauth "github.com/loggdme/strivia/oauth"
	strivia_oauth_providers "github.com/loggdme/strivia/oauth/providers"
)

func main() {
	google := strivia_oauth_providers.NewGitHubProvider("CLIENT_ID", "CLIENT_SECRET", nil)

	state := strivia_oauth.GenerateRandomState()

	authorizationURL := google.CreateAuthorizationURL(state, []string{"read:user user:email"})
	fmt.Printf("Please open the following URL in your browser:\n%s\n\n", authorizationURL)
	fmt.Printf("Please enter the code you received after authorizing:\n")

	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	code := input.Text()
	fmt.Printf("\n")

	tokens, _ := google.ValidateAuthorizationCode(code)
	user, _ := google.GetUser(tokens.AccessToken)
	fmt.Printf("%+v\n\n", user)
}
