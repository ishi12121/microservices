// internal/api/middleware.go
package api

import (
	"log"
	"net/http"
	"time"
)

// LoggerMiddleware logs request and response details
func LoggerMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		lw := &logResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
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