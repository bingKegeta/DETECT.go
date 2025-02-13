package websocket

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	"DETECT.go/internal/database" // Import your database package
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

var dbService database.Service // Database service for saving messages

// Initialize the WebSocket connection handler with the database service
func Init(db database.Service) {
	dbService = db
}

// Handle WebSocket connections
func handleWebSocketConnection(w http.ResponseWriter, r *http.Request) {
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
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading message:", err)
			break
		}

		// Log the incoming message for debugging
		log.Printf("Received WebSocket message: %s", p)

		// Parse the message assuming it's JSON with time, x, y values
		var gazeData map[string]interface{}
		if err := json.Unmarshal(p, &gazeData); err != nil {
			log.Println("Error parsing WebSocket message:", err)
			continue
		}

		// Extract the gaze data (time, x, y)
		time := gazeData["time"].(float64)
		x := gazeData["x"].(float64)
		y := gazeData["y"].(float64)

		// Send the gaze data to the Python service for analysis
		analysisResult, err := sendToPythonForAnalysis(time, x, y)
		if err != nil {
			log.Println("Error sending data to Python service:", err)
			continue
		}

		// Log the analysis result
		log.Printf("Analysis Result: %v", analysisResult)

		// Prepare the analysis result as a response to the client
		analysisResponse := map[string]interface{}{
			"variance":     analysisResult["variance"],
			"acceleration": analysisResult["acceleration"],
			"probability":  analysisResult["probability"],
		}

		// Convert the analysis result to JSON
		analysisResponseJSON, err := json.Marshal(analysisResponse)
		if err != nil {
			log.Println("Error marshalling analysis response:", err)
			continue
		}

		// Send the analysis result back to the client
		if err := conn.WriteMessage(messageType, analysisResponseJSON); err != nil {
			log.Println("Error writing message:", err)
			break
		}

		// Save the message to the database
		err = saveWebSocketMessage(string(p))
		if err != nil {
			log.Printf("Error saving WebSocket message to database: %v", err)
		} else {
			log.Printf("WebSocket message saved to database: %s", p)
		}
	}
}

// sendToPythonForAnalysis sends the gaze data to the Python Flask service and returns the result
func sendToPythonForAnalysis(time, x, y float64) (map[string]interface{}, error) {
	// Prepare the JSON request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"time": time,
		"x":    x,
		"y":    y,
	})
	if err != nil {
		return nil, err
	}

	// Send the request to the Python Flask server (assuming it's running on localhost:5000)
	resp, err := http.Post("http://localhost:5000/analyze", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse the response from Python
	var analysisResult map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&analysisResult); err != nil {
		return nil, err
	}

	return analysisResult, nil
}

// saveWebSocketMessage saves the incoming WebSocket message to the database
func saveWebSocketMessage(message string) error {
	// Save the message to the database (adjust the table and columns as needed)
	query := "INSERT INTO WebSocketMessages (message, timestamp) VALUES ($1, NOW())"
	_, err := dbService.GetDB().Exec(query, message) // Use GetDB() method to access the database
	if err != nil {
		log.Printf("Error executing query: %v", err)
		return err
	}
	return nil
}

// StartServer starts the WebSocket server on the given address
func StartServer() {
	http.HandleFunc("/ws", handleWebSocketConnection)
	log.Println("WebSocket server listening on ws://localhost:8080/ws")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Error starting server:", err)
	}
}
