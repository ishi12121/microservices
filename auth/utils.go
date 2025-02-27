package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// generateToken creates a cryptographically secure random token
func generateToken(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

// hashPassword securely hashes a password using bcrypt
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// checkPasswordHash compares a password against a hash
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// generateAuthTokens creates a new set of authentication tokens
func generateAuthTokens() AuthTokens {
	return AuthTokens{
		AccessToken:  generateToken(32),
		RefreshToken: generateToken(64),
		CSRFToken:    generateToken(32),
		ExpiresAt:    time.Now().Add(15 * time.Minute), // Access token expires in 15 minutes
	}
}

// refreshAuthTokens generates new access token using a valid refresh token
func refreshAuthTokens(refreshToken string, username string) (AuthTokens, error) {
	userData, exists := database[username]
	if !exists {
		return AuthTokens{}, errors.New("user not found")
	}
	
	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(refreshToken), []byte(userData.Tokens.RefreshToken)) != 1 {
		return AuthTokens{}, errors.New("invalid refresh token")
	}
	
	// Generate new tokens but keep the same refresh token
	newTokens := generateAuthTokens()
	newTokens.RefreshToken = userData.Tokens.RefreshToken
	
	return newTokens, nil
}