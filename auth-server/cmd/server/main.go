// cmd/server/main.go
package main

import (
	"auth-server/internal/api"
	"auth-server/internal/config"
	"auth-server/internal/database"
	"log"
	"os"
)

func main() {
	// Set up logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("Starting auth server...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database connection
	db, err := database.NewDatabase(cfg.Database.GetDatabaseURL())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create and configure server
	server := api.NewServer(db, cfg.Server.GetServerAddr(), cfg.Auth)
	server.SetupRoutes()

	// Start server
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
		os.Exit(1)
	}
}