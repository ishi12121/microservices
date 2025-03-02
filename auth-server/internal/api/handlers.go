// internal/api/handlers.go
package api

import (
	"auth-server/internal/auth"
	"auth-server/internal/database"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type Handler struct {
	DB        *database.Database
	TokenConf auth.TokenConfig
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RefreshTokenRequest struct {
	Username     string `json:"username"`
	RefreshToken string `json:"refreshToken"`
}

type AuthResponse struct {
	Message      string    `json:"message"`
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	CSRFToken    string    `json:"csrfToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received registration request for username: %s", req.Username)

	if len(req.Username) < 8 || len(req.Password) < 8 {
		sendJSONError(w, "Username and password must be at least 8 characters long", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	existingUser, err := h.DB.GetUserByUsername(ctx, req.Username)
	if err != nil {
		log.Printf("Error checking existing user: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if existingUser != nil {
		sendJSONError(w, "Username already exists", http.StatusConflict)
		return
	}

	// Hash password and create user
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, err = h.DB.CreateUser(ctx, req.Username, hashedPassword)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully registered user: %s", req.Username)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User registered successfully",
	})
}


func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user from database
	user, err := h.DB.GetUserByUsername(ctx, req.Username)
	if err != nil {
		log.Printf("Error retrieving user: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if user == nil || !auth.CheckPasswordHash(req.Password, user.HashedPassword) {
		sendJSONError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate new tokens
	tokens, err := auth.GenerateAuthTokens(h.TokenConf)
	if err != nil {
		log.Printf("Error generating tokens: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Save tokens to database
	dbToken := database.AuthToken{
		UserID:       user.ID,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		CSRFToken:    tokens.CSRFToken,
		ExpiresAt:    tokens.ExpiresAt,
	}

	if err := h.DB.SaveAuthTokens(ctx, user.ID, dbToken); err != nil {
		log.Printf("Error saving tokens: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("User logged in: %s", req.Username)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthResponse{
		Message:      "User logged in successfully",
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		CSRFToken:    tokens.CSRFToken,
		ExpiresAt:    tokens.ExpiresAt,
	})
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user from database
	user, err := h.DB.GetUserByUsername(ctx, req.Username)
	if err != nil {
		log.Printf("Error retrieving user: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		sendJSONError(w, "User not found", http.StatusNotFound)
		return
	}

	// Get stored tokens for user
	token, _, err := h.DB.GetAuthTokensByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		log.Printf("Error retrieving tokens: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if token == nil || token.UserID != user.ID || !auth.ValidateRefreshToken(req.RefreshToken, token.RefreshToken) {
		sendJSONError(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Generate new tokens but keep the same refresh token
	newTokens, err := auth.GenerateAuthTokens(h.TokenConf)
	if err != nil {
		log.Printf("Error generating tokens: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Keep the same refresh token
	newTokens.RefreshToken = token.RefreshToken

	// Save new tokens to database
	dbToken := database.AuthToken{
		UserID:       user.ID,
		AccessToken:  newTokens.AccessToken,
		RefreshToken: newTokens.RefreshToken,
		CSRFToken:    newTokens.CSRFToken,
		ExpiresAt:    newTokens.ExpiresAt,
	}

	if err := h.DB.SaveAuthTokens(ctx, user.ID, dbToken); err != nil {
		log.Printf("Error saving tokens: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("Tokens refreshed for user: %s", req.Username)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthResponse{
		Message:      "Tokens refreshed successfully",
		AccessToken:  newTokens.AccessToken,
		RefreshToken: newTokens.RefreshToken,
		CSRFToken:    newTokens.CSRFToken,
		ExpiresAt:    newTokens.ExpiresAt,
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	
	// Get access token from request
	accessToken := r.Header.Get("X-ACCESS-TOKEN")
	if accessToken == "" {
		sendJSONError(w, "Missing access token", http.StatusUnauthorized)
		return
	}

	// Get CSRF token from request
	csrfToken := r.Header.Get("X-CSRF-TOKEN")
	if csrfToken == "" {
		sendJSONError(w, "Missing CSRF token", http.StatusUnauthorized)
		return
	}

	// Get tokens from database
	token, user, err := h.DB.GetAuthTokensByAccessToken(ctx, accessToken)
	if err != nil {
		log.Printf("Error retrieving tokens: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if token == nil || user == nil {
		sendJSONError(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// Verify CSRF token
	if token.CSRFToken != csrfToken {
		sendJSONError(w, "Invalid CSRF token", http.StatusUnauthorized)
		return
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		sendJSONError(w, "Access token expired", http.StatusUnauthorized)
		return
	}

	// Delete tokens from database
	if err := h.DB.DeleteAuthTokens(ctx, user.ID); err != nil {
		log.Printf("Error deleting tokens: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("User logged out: %s", user.Username)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User logged out successfully",
	})
}

func (h *Handler) Protected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	
	// Get tokens from request headers
	accessToken := r.Header.Get("X-ACCESS-TOKEN")
	if accessToken == "" {
		sendJSONError(w, "Missing access token", http.StatusUnauthorized)
		return
	}

	csrfToken := r.Header.Get("X-CSRF-TOKEN")
	if csrfToken == "" {
		sendJSONError(w, "Missing CSRF token", http.StatusUnauthorized)
		return
	}

	// Get tokens from database
	token, user, err := h.DB.GetAuthTokensByAccessToken(ctx, accessToken)
	if err != nil {
		log.Printf("Error retrieving tokens: %v", err)
		sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if token == nil || user == nil {
		sendJSONError(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// Verify CSRF token
	if token.CSRFToken != csrfToken {
		sendJSONError(w, "Invalid CSRF token", http.StatusUnauthorized)
		return
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		sendJSONError(w, "Access token expired", http.StatusUnauthorized)
		return
	}

	log.Printf("Protected resource accessed by user: %s", user.Username)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Protected resource accessed by user: " + user.Username,
	})
}

func sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}