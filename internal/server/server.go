package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"DETECT.go/internal/database"
)

// Server struct
type Server struct {
	port int
	db   database.Service
}

/*
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        	origin := r.Header.Get("Origin")

        	if origin != "" && (strings.HasSuffix(origin, ".vercel.app") || origin == "https://detect-js-nine.vercel.app") {
        		w.Header().Set("Access-Control-Allow-Origin", origin)
        		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        		w.Header().Set("Access-Control-Allow-Credentials", "true")
        	}

        	if r.Method == http.MethodOptions {
        		w.WriteHeader(http.StatusNoContent)
        		return
        	}

        	next.ServeHTTP(w, r)
	})
}*/

// NewServer initializes and returns an HTTP server
func NewServer() *http.Server {
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	serverInstance := &Server{
		port: port,
		db:   database.New(),
	}

	handler := serverInstance.RegisterRoutes()

	// Configure HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", serverInstance.port),
		Handler:      handler,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server
}
