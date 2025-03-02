// internal/config/config.go
package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"auth-server/internal/auth"
	"database/sql"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
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
func (c *DatabaseConfig) GetDatabaseURL()  string {
    log.Printf("Attempting to connect to database")
    
    db, err := sql.Open("postgres", c.URL)
    if err != nil {
        log.Printf("Error opening database connection: %v", err)
        return c.URL
    }
    defer db.Close()

    var result int
    err = db.QueryRow("SELECT 1+1").Scan(&result)
    if err != nil {
        log.Printf("Database connection test failed: %v", err)
        return c.URL
    }

    if result == 2 {
        log.Printf("Database connection test successful")
    } else {
        log.Printf("Database connection test returned unexpected result: %d", result)
    }

    return c.URL
}

// GetDatabaseWithLogging returns a database connection with query logging enabled
func (c *DatabaseConfig) GetDatabaseWithLogging() (*sql.DB, error) {
    log.Printf("Attempting to connect to database with query logging")
    
    // Open database connection
    db, err := sql.Open("postgres", c.URL)
    if err != nil {
        log.Printf("Error opening database connection: %v", err)
        return nil, err
    }
    
    // Test connection
    var result int
    err = db.QueryRow("SELECT 1+1").Scan(&result)
    if err != nil {
        log.Printf("Database connection test failed: %v", err)
        db.Close()
        return nil, err
    }
    
    if result == 2 {
        log.Printf("Database connection test successful")
    } else {
        log.Printf("Database connection test returned unexpected result: %d", result)
    }
    
    // Enable query logging by setting a driver-specific logger
    // For PostgreSQL, we can use a custom driver
    driver := &LoggingDriver{parent: db.Driver()}
    sql.Register("postgres-logging", driver)
    
    // Open a new connection with the logging driver
    dbWithLogging, err := sql.Open("postgres-logging", c.URL)
    if err != nil {
        log.Printf("Error opening logging database connection: %v", err)
        db.Close()
        return nil, err
    }
    
    db.Close() // Close the original connection
    
    return dbWithLogging, nil
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
