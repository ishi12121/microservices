package main

import (
	"errors"
	"log"
	"net/http"
	"time"
)

var ErrAuth = errors.New("Unauthorized")

// AuthTokens represents the authentication tokens
type AuthTokens struct {
	AccessToken  string
	RefreshToken string
	CSRFToken    string
	ExpiresAt    time.Time
}

// Authorize validates access and CSRF tokens from the request
func Authorize(r *http.Request) error {
	// Get the access token from the header
	accessToken := r.Header.Get("X-ACCESS-TOKEN")
	if accessToken == "" {
		return ErrAuth
	}
	
	log.Printf("Access Token: %s", accessToken)
	
	// Get the CSRF token from the header
	csrfToken := r.Header.Get("X-CSRF-TOKEN")
	if csrfToken == "" {
		return ErrAuth
	}
	log.Printf("CSRF Token: %s", csrfToken)
	
	// Find the user with this access token
	foundValidUser := false
	for _, userData := range database {
		if userData.Tokens.AccessToken == accessToken {
			// Check if token is expired
			if time.Now().After(userData.Tokens.ExpiresAt) {
				return errors.New("access token expired")
			}
			
			// Verify CSRF token
			if userData.Tokens.CSRFToken == csrfToken {
				foundValidUser = true
				break
			}
		}
	}
	
	if !foundValidUser {
		return ErrAuth
	}
	
	return nil
}