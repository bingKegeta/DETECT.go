package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"DETECT.go/internal/database"
)

// Server struct for handling server configuration
type Server struct {
	port int
	db   database.Service
}

// NewServer initializes and returns an HTTP server.
func NewServer() *http.Server {
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	serverInstance := &Server{
		port: port,
	}

	handler := serverInstance.RegisterRoutes()

	// Configure the HTTP server
	apiServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", serverInstance.port),
		Handler:      handler,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return apiServer
}
