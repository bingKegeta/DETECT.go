package websocket

import (
	"encoding/json"
	"fmt"
	"net/http"

	"DETECT.go/internal/analysis"
	"github.com/gorilla/websocket"
)

type GazeData struct {
	Time float64 `json:"time"`
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
}

type AnalysisResponse struct {
	Variance     float64 `json:"variance"`
	Acceleration float64 `json:"acceleration"`
	Probability  float64 `json:"probability"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func NewWebSocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			fmt.Println("WebSocket upgrade failed:", err)
			return
		}
		defer conn.Close()

		for {
			// Handle incoming WebSocket messages
			messageType, p, err := conn.ReadMessage()
			if err != nil {
				fmt.Println("Error reading WebSocket message:", err)
				break
			}

			// Parse the incoming JSON message to extract gaze data
			var gazeData GazeData
			err = json.Unmarshal(p, &gazeData)
			if err != nil {
				fmt.Println("Error parsing WebSocket message:", err)
				break
			}

			// Call the analysis function to get the result
			variance, acceleration, probability := analysis.AnalyzeGazeData(gazeData.Time, gazeData.X, gazeData.Y)

			// Prepare the response message to send back to the client
			analysisResponse := map[string]interface{}{
				"variance":     variance,
				"acceleration": acceleration,
				"probability":  probability,
			}

			// Marshal the analysis response to JSON
			responseJSON, err := json.Marshal(analysisResponse)
			if err != nil {
				fmt.Println("Error marshaling analysis response:", err)
				break
			}

			// Send the analysis response back to the WebSocket client
			if err := conn.WriteMessage(messageType, responseJSON); err != nil {
				fmt.Println("Error writing WebSocket message:", err)
				break
			}
		}
	})
}
