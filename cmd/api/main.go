package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"DETECT.go/internal/analysis"
	"DETECT.go/internal/auth"
	"DETECT.go/internal/server"
	"github.com/gorilla/websocket"
)

// WebSocket handler to manage incoming WebSocket connections
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow connections from any origin
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading connection:", err)
		return
	}
	defer conn.Close()

	log.Println("WebSocket connected")

	// Read messages from the WebSocket
	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading WebSocket message:", err)
			break
		}

		// Parse the incoming JSON message to extract gaze data
		var gazeData struct {
			Time float64 `json:"time"`
			X    float64 `json:"x"`
			Y    float64 `json:"y"`
		}
		err = json.Unmarshal(msg, &gazeData)
		if err != nil {
			log.Println("Error parsing WebSocket message:", err)
			break
		}

		// Call the analysis function to get the result (variance, acceleration, probability)
		variance, acceleration, probability := analysis.AnalyzeGazeData(gazeData.Time, gazeData.X, gazeData.Y)

		// Prepare the response message to send back to the client
		analysisResponse := struct {
			Variance     float64 `json:"variance"`
			Acceleration float64 `json:"acceleration"`
			Probability  float64 `json:"probability"`
		}{
			Variance:     variance,
			Acceleration: acceleration,
			Probability:  probability,
		}

		// Marshal the analysis response to JSON
		responseJSON, err := json.Marshal(analysisResponse)
		if err != nil {
			log.Println("Error marshaling analysis response:", err)
			break
		}

		// Send the analysis response back to the WebSocket client
		if err := conn.WriteMessage(messageType, responseJSON); err != nil {
			log.Println("Error writing WebSocket message:", err)
			break
		}
	}
}

func gracefulShutdown(apiServer *http.Server, done chan bool) {
	// Create context that listens for the interrupt signal from the OS.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Listen for the interrupt signal.
	<-ctx.Done()

	log.Println("Shutting down gracefully, press Ctrl+C again to force")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown with error: %v", err)
	}

	log.Println("Server exiting")

	// Notify the main goroutine that the shutdown is complete
	done <- true
}

func main() {
	// Initialize authentication and server
	auth.NewAuth()
	server := server.NewServer()

	// Create a done channel to signal when the shutdown is complete
	done := make(chan bool, 1)

	// Run graceful shutdown in a separate goroutine
	go gracefulShutdown(server, done)

	// Start WebSocket server on port 9090
	go func() {
		wsServer := &http.Server{
			Addr:    ":9090",
			Handler: http.HandlerFunc(handleWebSocket), // Handle WebSocket connections
		}

		log.Println("Starting WebSocket server on port 9090...")
		if err := wsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("WebSocket server error: %s", err)
		}
	}()

	// Start the main server (your HTTP server)
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		panic(fmt.Sprintf("HTTP server error: %s", err))
	}

	// Wait for the graceful shutdown to complete
	<-done
	log.Println("Graceful shutdown complete.")
}
