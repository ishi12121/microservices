// internal/api/server.go
package api

import (
	"auth-server/internal/auth"
	"auth-server/internal/database"
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Server represents the HTTP server
type Server struct {
	db         *database.Database
	server     *http.Server
	tokenConf  auth.TokenConfig
}

// NewServer creates a new server instance
func NewServer(db *database.Database, addr string, tokenConf auth.TokenConfig) *Server {
	return &Server{
		db:        db,
		tokenConf: tokenConf,
		server: &http.Server{
			Addr:         addr,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}
}

// SetupRoutes configures all the routes for the server
func (s *Server) SetupRoutes() {
	handler := &Handler{
		DB:        s.db,
		TokenConf: s.tokenConf,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/register", LoggerMiddleware(handler.Register))
	mux.HandleFunc("/login", LoggerMiddleware(handler.Login))
	mux.HandleFunc("/refresh", LoggerMiddleware(handler.RefreshToken))
	mux.HandleFunc("/logout", LoggerMiddleware(handler.Logout))
	mux.HandleFunc("/protected", LoggerMiddleware(handler.Protected))

	s.server.Handler = mux
}

// Start begins the server and handles graceful shutdown
func (s *Server) Start() error {
	// Channel for server errors
	errChan := make(chan error, 1)

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on %s...", s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Channel for OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Block until signal or error
	select {
	case err := <-errChan:
		return err
	case <-stop:
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.server.Shutdown(ctx); err != nil {
			return err
		}
		log.Println("Server gracefully stopped")
	}

	return nil
}