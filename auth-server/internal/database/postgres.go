// internal/database/postgres.go
package database

import (
	"auth-server/internal/util"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type Database struct {
	DB *sqlx.DB
}

func NewDatabase(connectionString string) (*Database, error) {
    defer util.Trace()() 
	db, err := sqlx.Connect("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Verify connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Database{DB: db}, nil
}

func (d *Database) Close() error {
	return d.DB.Close()
}

// User methods
func (d *Database) CreateUser(ctx context.Context, username, hashedPassword string) (int, error) {
    defer util.Trace()() 
	query := `
		INSERT INTO users (username, hashed_password)
		VALUES ($1, $2)
		RETURNING id
	`
	var id int
	err := d.DB.GetContext(ctx, &id, query, username, hashedPassword)
	if err != nil {
		return 0, fmt.Errorf("failed to create user: %w", err)
	}
	return id, nil
}

func (d *Database) GetUserByUsername(ctx context.Context, username string) (*User, error) {
    defer util.Trace()() 
	query := `
		SELECT id, username, hashed_password, created_at, updated_at
		FROM users
		WHERE username = $1
	`
	var user User
	err := d.DB.GetContext(ctx, &user, query, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // User not found
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// Auth token methods
func (d *Database) SaveAuthTokens(ctx context.Context, userID int, tokens AuthToken) error {
    defer util.Trace()() 
	// First delete any existing tokens for this user
	_, err := d.DB.ExecContext(ctx, "DELETE FROM auth_tokens WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("failed to delete existing tokens: %w", err)
	}

	query := `
		INSERT INTO auth_tokens (user_id, access_token, refresh_token, csrf_token, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = d.DB.ExecContext(ctx, query, userID, tokens.AccessToken, tokens.RefreshToken, tokens.CSRFToken, tokens.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to save auth tokens: %w", err)
	}
	return nil
}

func (d *Database) GetAuthTokensByAccessToken(ctx context.Context, accessToken string) (*AuthToken, *User, error) {
    defer util.Trace()() 
    query := `
        SELECT 
            t.id, t.user_id, t.access_token, t.refresh_token, t.csrf_token, t.expires_at, t.created_at,
            u.id as user_id, u.username, u.hashed_password, u.created_at as user_created_at, u.updated_at as user_updated_at
        FROM auth_tokens t
        JOIN users u ON t.user_id = u.id
        WHERE t.access_token = $1
    `
    
    type JoinResult struct {
        ID           int       `db:"id"`
        UserID       int       `db:"user_id"`
        AccessToken  string    `db:"access_token"`
        RefreshToken string    `db:"refresh_token"`
        CSRFToken    string    `db:"csrf_token"`
        ExpiresAt    time.Time `db:"expires_at"`
        CreatedAt    time.Time `db:"created_at"`
        
        Username       string    `db:"username"`
        HashedPassword string    `db:"hashed_password"`
        UserCreatedAt  time.Time `db:"user_created_at"`
        UserUpdatedAt  time.Time `db:"user_updated_at"`
    }
    
    var result JoinResult
    err := d.DB.GetContext(ctx, &result, query, accessToken)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, nil, nil // Not found
        }
        return nil, nil, fmt.Errorf("failed to query auth tokens: %w", err)
    }
    
    token := &AuthToken{
        ID:           result.ID,
        UserID:       result.UserID,
        AccessToken:  result.AccessToken,
        RefreshToken: result.RefreshToken,
        CSRFToken:    result.CSRFToken,
        ExpiresAt:    result.ExpiresAt,
        CreatedAt:    result.CreatedAt,
    }
    
    user := &User{
        ID:             result.UserID,
        Username:       result.Username,
        HashedPassword: result.HashedPassword,
        CreatedAt:      result.UserCreatedAt,
        UpdatedAt:      result.UserUpdatedAt,
    }
    
    return token, user, nil
}

func (d *Database) GetAuthTokensByRefreshToken(ctx context.Context, refreshToken string) (*AuthToken, *User, error) {
    defer util.Trace()() 
    query := `
        SELECT 
            t.id, t.user_id, t.access_token, t.refresh_token, t.csrf_token, t.expires_at, t.created_at,
            u.id as user_id, u.username, u.hashed_password, u.created_at as user_created_at, u.updated_at as user_updated_at
        FROM auth_tokens t
        JOIN users u ON t.user_id = u.id
        WHERE t.refresh_token = $1
    `
    
    type JoinResult struct {
        ID           int       `db:"id"`
        UserID       int       `db:"user_id"`
        AccessToken  string    `db:"access_token"`
        RefreshToken string    `db:"refresh_token"`
        CSRFToken    string    `db:"csrf_token"`
        ExpiresAt    time.Time `db:"expires_at"`
        CreatedAt    time.Time `db:"created_at"`
        
        Username       string    `db:"username"`
        HashedPassword string    `db:"hashed_password"`
        UserCreatedAt  time.Time `db:"user_created_at"`
        UserUpdatedAt  time.Time `db:"user_updated_at"`
    }
    
    var result JoinResult
    err := d.DB.GetContext(ctx, &result, query, refreshToken)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, nil, nil // Not found
        }
        return nil, nil, fmt.Errorf("failed to query auth tokens: %w", err)
    }
    
    token := &AuthToken{
        ID:           result.ID,
        UserID:       result.UserID,
        AccessToken:  result.AccessToken,
        RefreshToken: result.RefreshToken,
        CSRFToken:    result.CSRFToken,
        ExpiresAt:    result.ExpiresAt,
        CreatedAt:    result.CreatedAt,
    }
    
    user := &User{
        ID:             result.UserID,
        Username:       result.Username,
        HashedPassword: result.HashedPassword,
        CreatedAt:      result.UserCreatedAt,
        UpdatedAt:      result.UserUpdatedAt,
    }
    
    return token, user, nil
}

func (d *Database) DeleteAuthTokens(ctx context.Context, userID int) error {
    defer util.Trace()() 
	_, err := d.DB.ExecContext(ctx, "DELETE FROM auth_tokens WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("failed to delete auth tokens: %w", err)
	}
	return nil
}