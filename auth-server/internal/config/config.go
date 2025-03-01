// internal/config/config.go
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"auth-server/internal/auth"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Auth     auth.TokenConfig
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Host string
	Port int
}

// DatabaseConfig holds database-related configuration
type DatabaseConfig struct {
    URL string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
    // Load .env file if it exists
    godotenv.Load()
    
    // Server config
    serverHost := getEnv("SERVER_HOST", "localhost")
    serverPortStr := getEnv("SERVER_PORT", "8080")
    serverPort, err := strconv.Atoi(serverPortStr)
    if err != nil {
        return nil, fmt.Errorf("invalid server port: %w", err)
    }
    
    // Database config - now using a direct URL
    dbURL := getEnv("DATABASE_URL", "postgresql://localhost:5432/dbname")
    
    // Parse durations for tokens
    accessTokenDurationStr := getEnv("ACCESS_TOKEN_DURATION", "15m")
    accessTokenDuration, err := time.ParseDuration(accessTokenDurationStr)
    if err != nil {
        return nil, fmt.Errorf("invalid access token duration: %w", err)
    }
    
    refreshTokenDurationStr := getEnv("REFRESH_TOKEN_DURATION", "168h")
    refreshTokenDuration, err := time.ParseDuration(refreshTokenDurationStr)
    if err != nil {
        return nil, fmt.Errorf("invalid refresh token duration: %w", err)
    }
    
    return &Config{
        Server: ServerConfig{
            Host: serverHost,
            Port: serverPort,
        },
        Database: DatabaseConfig{
            URL: dbURL,
        },
        Auth: auth.TokenConfig{
            AccessTokenDuration: accessTokenDuration,
            RefreshTokenDuration: refreshTokenDuration,
        },
    }, nil
}

// GetDatabaseURL returns the database connection string
func (c *DatabaseConfig) GetDatabaseURL() string {
    return c.URL
}

// GetServerAddr returns the formatted server address
func (c *ServerConfig) GetServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Helper function to get environment variables with default values
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}