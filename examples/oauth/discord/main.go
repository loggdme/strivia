package main

import (
	"bufio"
	"fmt"
	"os"

	strivia_oauth "github.com/loggdme/strivia/oauth"
	strivia_oauth_providers "github.com/loggdme/strivia/oauth/providers"
)

func main() {
	discord := strivia_oauth_providers.NewDiscordProvider("CLIENT_ID", "CLIENT_SECRET", "http://localhost:8080")

	state := strivia_oauth.GenerateRandomState()

	authorizationURL := discord.CreateAuthorizationURL(state, []string{"identify", "email"})
	fmt.Printf("Please open the following URL in your browser:\n%s\n\n", authorizationURL)
	fmt.Printf("Please enter the code you received after authorizing:\n")

	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	code := input.Text()
	fmt.Printf("\n")

	tokens, _ := discord.ValidateAuthorizationCode(code)
	user, _ := discord.GetUser(tokens.AccessToken)
	fmt.Printf("%+v\n\n", user)
}
