package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/joho/godotenv/autoload"

	"DETECT.go/internal/analysis"
	"DETECT.go/internal/database"
)

// Server struct
type Server struct {
	port int
	db   database.Service
}

// WebSocket server instance
var wsServer *http.Server

// NewServer initializes and returns an HTTP server
func NewServer() *http.Server {
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	serverInstance := &Server{
		port: port,
		db:   database.New(),
	}

	// Configure HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", serverInstance.port),
		Handler:      serverInstance.RegisterRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server
}

// HandleWebSocket processes WebSocket connections and gaze data
func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading WebSocket connection:", err)
		return
	}
	defer conn.Close()

	log.Println("WebSocket connected")

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading WebSocket message:", err)
			break
		}

		// Parse the incoming JSON message
		var gazeData struct {
			Time float64 `json:"time"`
			X    float64 `json:"x"`
			Y    float64 `json:"y"`
		}
		if err := json.Unmarshal(msg, &gazeData); err != nil {
			log.Println("Error parsing WebSocket message:", err)
			break
		}

		// Analyze gaze data
		variance, acceleration, probability := analysis.AnalyzeGazeData(gazeData.Time, gazeData.X, gazeData.Y)

		// Prepare response
		analysisResponse := struct {
			Variance     float64 `json:"variance"`
			Acceleration float64 `json:"acceleration"`
			Probability  float64 `json:"probability"`
		}{
			Variance:     variance,
			Acceleration: acceleration,
			Probability:  probability,
		}

		// Send response to client
		responseJSON, err := json.Marshal(analysisResponse)
		if err != nil {
			log.Println("Error marshaling analysis response:", err)
			break
		}

		if err := conn.WriteMessage(websocket.TextMessage, responseJSON); err != nil {
			log.Println("Error writing WebSocket message:", err)
			break
		}
	}
}

// RunWebSocketServer starts the WebSocket server and supports graceful shutdown
func RunWebSocketServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", HandleWebSocket)

	wsServer = &http.Server{
		Addr:    ":9090",
		Handler: mux,
	}

	// Channel to listen for shutdown signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Println("Starting WebSocket server on :9090")
		if err := wsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("WebSocket server error: %v", err)
		}
	}()

	<-quit
	log.Println("Shutting down WebSocket server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := wsServer.Shutdown(ctx); err != nil {
		log.Fatalf("WebSocket server forced to shutdown: %v", err)
	}

	log.Println("WebSocket server exited cleanly")
}
