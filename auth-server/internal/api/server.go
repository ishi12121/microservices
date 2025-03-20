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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server represents the HTTP server
type Server struct {
	db         *database.Database
	server     *http.Server
	tokenConf  auth.TokenConfig
	metrics    *Metrics
}
type Metrics struct {
    requestsTotal     *prometheus.CounterVec
    requestDuration   *prometheus.HistogramVec
    activeConnections prometheus.Gauge
}


func NewMetrics() *Metrics {
    m := &Metrics{
        requestsTotal: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "http_requests_total",
                Help: "Total number of HTTP requests",
            },
            []string{"method", "endpoint", "status"},
        ),
        requestDuration: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name:    "http_request_duration_seconds",
                Help:    "Duration of HTTP requests in seconds",
                Buckets: prometheus.DefBuckets,
            },
            []string{"method", "endpoint"},
        ),
        activeConnections: prometheus.NewGauge(
            prometheus.GaugeOpts{
                Name: "http_active_connections",
                Help: "Number of active HTTP connections",
            },
        ),
    }
    
    // Register metrics with Prometheus
    prometheus.MustRegister(m.requestsTotal)
    prometheus.MustRegister(m.requestDuration)
    prometheus.MustRegister(m.activeConnections)
    
    return m
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
        metrics: NewMetrics(),
    }
}

func (s *Server) MetricsMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Increment active connections
        s.metrics.activeConnections.Inc()
        defer s.metrics.activeConnections.Dec()
        
        // Track request duration
        start := time.Now()
        
        // Create a wrapper to capture the status code
        wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
        
        // Call the next handler
        next(wrapper, r)
        
        // Record metrics
        duration := time.Since(start).Seconds()
        s.metrics.requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
        s.metrics.requestsTotal.WithLabelValues(r.Method, r.URL.Path, http.StatusText(wrapper.statusCode)).Inc()
    }
}

type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}

// SetupRoutes configures all the routes for the server
func (s *Server) SetupRoutes() {
    handler := &Handler{
        DB:        s.db,
        TokenConf: s.tokenConf,
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/register", s.MetricsMiddleware(LoggerMiddleware(handler.Register)))
    mux.HandleFunc("/login", s.MetricsMiddleware(LoggerMiddleware(handler.Login)))
    mux.HandleFunc("/refresh", s.MetricsMiddleware(LoggerMiddleware(handler.RefreshToken)))
    mux.HandleFunc("/logout", s.MetricsMiddleware(LoggerMiddleware(handler.Logout)))
    mux.HandleFunc("/protected", s.MetricsMiddleware(LoggerMiddleware(handler.Protected)))
    
    // Add Prometheus metrics endpoint
    mux.Handle("/metrics", promhttp.Handler())

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