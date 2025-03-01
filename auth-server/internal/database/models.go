// internal/database/models.go
package database

import (
	"time"
)

type User struct {
	ID             int       `db:"id"`
	Username       string    `db:"username"`
	HashedPassword string    `db:"hashed_password"`
	CreatedAt      time.Time `db:"created_at"`
	UpdatedAt      time.Time `db:"updated_at"`
}

type AuthToken struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	AccessToken  string    `db:"access_token"`
	RefreshToken string    `db:"refresh_token"`
	CSRFToken    string    `db:"csrf_token"`
	ExpiresAt    time.Time `db:"expires_at"`
	CreatedAt    time.Time `db:"created_at"`
}