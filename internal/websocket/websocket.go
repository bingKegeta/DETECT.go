package websocket

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

// Handle WebSocket connections
func HandleWebSocketConnection(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading connection:", err)
		return
	}
	defer conn.Close()

	// Read messages from WebSocket connection
	for {
		// Read the next message from the client
		_, p, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading message:", err)
			break
		}

		// Log the incoming message for debugging
		fmt.Printf("Received WebSocket message: %s\n", p)

		// Send a simple echo back to the client
		if err := conn.WriteMessage(websocket.TextMessage, p); err != nil {
			log.Println("Error sending message:", err)
			break
		}
	}
}

// StartServer starts the WebSocket server on the given address
func StartServer() error {
	http.HandleFunc("/ws", HandleWebSocketConnection)
	fmt.Println("WebSocket server listening on ws://localhost:9090")
	return http.ListenAndServe("0.0.0.0:9090", nil) // Return error if ListenAndServe fails
}
