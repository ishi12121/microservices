// internal/auth/tokens.go
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"time"
)

// TokenConfig contains configuration for token generation
type TokenConfig struct {
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
}

// DefaultTokenConfig provides sensible defaults
var DefaultTokenConfig = TokenConfig{
	AccessTokenDuration:  15 * time.Minute,
	RefreshTokenDuration: 7 * 24 * time.Hour, // 7 days
}

// Tokens represents the authentication tokens
type Tokens struct {
	AccessToken  string
	RefreshToken string
	CSRFToken    string
	ExpiresAt    time.Time
}

// GenerateToken creates a cryptographically secure random token
func GenerateToken(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateAuthTokens creates a new set of authentication tokens
func GenerateAuthTokens(config TokenConfig) (Tokens, error) {
	accessToken, err := GenerateToken(32)
	if err != nil {
		return Tokens{}, err
	}

	refreshToken, err := GenerateToken(64)
	if err != nil {
		return Tokens{}, err
	}

	csrfToken, err := GenerateToken(32)
	if err != nil {
		return Tokens{}, err
	}

	return Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CSRFToken:    csrfToken,
		ExpiresAt:    time.Now().Add(config.AccessTokenDuration),
	}, nil
}

// ValidateRefreshToken compares refresh tokens using constant-time comparison
func ValidateRefreshToken(providedToken, storedToken string) bool {
	return subtle.ConstantTimeCompare([]byte(providedToken), []byte(storedToken)) == 1
}