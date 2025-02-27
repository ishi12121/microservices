package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	Tokens         AuthTokens
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

func sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

func loggerMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		lw := &logResponseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}

		log.Printf(
			"Request: Method=%s Path=%s",
			r.Method,
			r.URL.Path,
		)

		next(lw, r)

		duration := time.Since(startTime)
		log.Printf(
			"Response: Status=%d Duration=%v",
			lw.statusCode,
			duration,
		)
	}
}

type logResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lw *logResponseWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.ResponseWriter.WriteHeader(code)
}

var database = map[string]Login{}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	log.Println("Server starting on port 8080...")

	http.HandleFunc("/register", loggerMiddleware(register))
	http.HandleFunc("/login", loggerMiddleware(login))
	http.HandleFunc("/refresh", loggerMiddleware(refreshToken))
	http.HandleFunc("/logout", loggerMiddleware(logout))
	http.HandleFunc("/protected", loggerMiddleware(protected))

	log.Fatal(http.ListenAndServe(":8080", nil))
}


//** public api **//
//** payload **//
// {
// 	"username": "user1",
// 	"password": "password1"
// }

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received registration request for username: %s", req.Username)

	if len(req.Username) < 8 || len(req.Password) < 8 {
		sendJSONError(w, "Username and password must be at least 8 characters long", http.StatusNotAcceptable)
		return
	}

	if _, ok := database[req.Username]; ok {
		sendJSONError(w, "Username already exists", http.StatusConflict)
		return
	}

	hashedPassword, _ := hashPassword(req.Password)
	database[req.Username] = Login{
		HashedPassword: hashedPassword,
		Tokens:         AuthTokens{}, // Empty tokens until login
	}

	log.Printf("Successfully registered user: %s", req.Username)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User registered successfully",
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	password := req.Password
	user, ok := database[username]
	if !ok || !checkPasswordHash(password, user.HashedPassword) {
		sendJSONError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate new tokens
	tokens := generateAuthTokens()
	
	// Store tokens in the database
	user.Tokens = tokens
	database[username] = user

	log.Printf("User logged in: %s", username)
	
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

func refreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	username := req.Username
	refreshToken := req.RefreshToken
	
	newTokens, err := refreshAuthTokens(refreshToken, username)
	if err != nil {
		sendJSONError(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}
	
	// Update tokens in database
	user := database[username]
	user.Tokens = newTokens
	database[username] = user
	
	log.Printf("Tokens refreshed for user: %s", username)
	
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

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	if err := Authorize(r); err != nil {
		sendJSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Clear the tokens from the database
	username := req.Username
	if user, exists := database[username]; exists {
		user.Tokens = AuthTokens{} // Reset tokens
		database[username] = user
		
		log.Printf("User logged out: %s", username)
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "User logged out successfully",
		})
	} else {
		sendJSONError(w, "User not found", http.StatusNotFound)
	}
}

func protected(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        sendJSONError(w, "Invalid method", http.StatusMethodNotAllowed)
        return
    }
    
    // Parse the request body first to get the username
    var req struct {
        Username string `json:"username"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        sendJSONError(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Check if user exists
    username := req.Username
    userData, exists := database[username]
    if !exists {
        sendJSONError(w, "User not found", http.StatusNotFound)
        return
    }
    
    // Get tokens from request headers
    accessToken := r.Header.Get("X-ACCESS-TOKEN")
    csrfToken := r.Header.Get("X-CSRF-TOKEN")
    
    // Verify tokens are present
    if accessToken == "" || csrfToken == "" {
        sendJSONError(w, "Missing authentication tokens", http.StatusUnauthorized)
        return
    }
    
    // Verify tokens belong to the user and are valid
    if userData.Tokens.AccessToken != accessToken || 
       userData.Tokens.CSRFToken != csrfToken {
        sendJSONError(w, "Invalid authentication tokens", http.StatusUnauthorized)
        return
    }
    
    // Check if access token is expired
    if time.Now().After(userData.Tokens.ExpiresAt) {
        sendJSONError(w, "Access token expired", http.StatusUnauthorized)
        return
    }
    
    log.Printf("Protected resource accessed by user: %s", username)
    
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "message": fmt.Sprintf("Protected resource accessed by user: %s", username),
    })
}