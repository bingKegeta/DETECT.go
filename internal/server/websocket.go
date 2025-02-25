package server

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

const (
	pongWait   = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10
)

// clientManager maintains active WebSocket connections.
type clientManager struct {
	clients map[string]*websocket.Conn
	mu      sync.Mutex
}

var manager = clientManager{
	clients: make(map[string]*websocket.Conn),
}

// WebSocketHandler upgrades the connection and handles communication.
func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	// You can add session validation/authentication here.
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id is required", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "Failed to upgrade connection", http.StatusInternalServerError)
		return
	}

	// Register client
	manager.mu.Lock()
	manager.clients[userID] = conn
	manager.mu.Unlock()

	// Ensure cleanup on disconnect
	defer func() {
		manager.mu.Lock()
		delete(manager.clients, userID)
		manager.mu.Unlock()
		conn.Close()
	}()

	// Set up ping/pong to maintain connection health.
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// Start a goroutine to send periodic pings.
	go func() {
		ticker := time.NewTicker(pingPeriod)
		defer ticker.Stop()
		for range ticker.C {
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}()

	// Read messages from the client.
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("read error from %s: %v", userID, err)
			break
		}
		// Example: echo the message back.
		if err := conn.WriteMessage(messageType, message); err != nil {
			log.Printf("write error to %s: %v", userID, err)
			break
		}
	}
}
