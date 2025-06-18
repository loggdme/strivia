package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"

	strivia_oauth "github.com/loggdme/strivia/oauth"
	strivia_oauth_providers "github.com/loggdme/strivia/oauth/providers"
)

var (
	googleProvider = strivia_oauth_providers.NewGoogleProvider("CLIENT_ID", "CLIENT_SECRET", "http://localhost:8080/auth/google/callback")
	stateStore     = struct {
		sync.Mutex
		state        string
		codeVerifier string
	}{}
)

func main() {
	http.HandleFunc("/auth/google", handleGoogleAuth)
	http.HandleFunc("/auth/google/callback", handleGoogleCallback)
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./examples/oauth/_test_server/views/login.html")
	})
	http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./examples/oauth/_test_server/views/profile.html")
	})
	fmt.Println("Server started at http://localhost:8080/login")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleGoogleAuth(w http.ResponseWriter, r *http.Request) {
	state := strivia_oauth.GenerateRandomState()
	codeVerifier := strivia_oauth.GenerateCodeVerifier()

	stateStore.Lock()
	stateStore.state = state
	stateStore.codeVerifier = codeVerifier
	stateStore.Unlock()

	authURL := googleProvider.CreateAuthorizationURL(state, codeVerifier, []string{"openid", "profile", "email"})

	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	fmt.Println(code, state)

	stateStore.Lock()
	expectedState := stateStore.state
	codeVerifier := stateStore.codeVerifier
	stateStore.Unlock()

	if state != expectedState {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	tokens, err := googleProvider.ValidateAuthorizationCode(code, codeVerifier)
	if err != nil {
		http.Error(w, "Failed to validate code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("http://localhost:8080/profile?token=%s", *tokens.IdToken), http.StatusFound)
}
