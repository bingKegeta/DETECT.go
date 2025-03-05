package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"sync"
	"time"

	//"strconv"

	"DETECT.go/internal/database"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/markbates/goth/gothic"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

// clientManager maintains active WebSocket connections.
type clientManager struct {
	clients map[string]*websocket.Conn
	mu      sync.Mutex
}

var manager = clientManager{
	clients: make(map[string]*websocket.Conn),
}

func init() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Read the secret from .env
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatalf("JWT_SECRET is not set in the .env file")
	}

	jwtSecret = []byte(secret)
}

// WebSocketHandler upgrades the connection and handles communication.
func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	// You can add session validation/authentication here.
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id is required", http.StatusUnauthorized)
		return
	}

	// Correctly call Upgrade on the struct instance
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil) // Call the method on the struct, not a pointer
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
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Start a goroutine to send periodic pings.
	go func() {
		ticker := time.NewTicker((60 * time.Second * 9) / 10)
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

func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	environment := os.Getenv("CLIENT_URL")
	if environment == "" {
		log.Fatalf("CLIENT_URL is not set in the .env file")
	}
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{environment},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/", s.HelloWorldHandler)
	r.Get("/health", s.healthHandler)
	r.Get("/websocket", WebSocketHandler)
	r.Post("/login", s.handleLogin)
	r.Post("/register", s.handleRegister)
	r.Get("/auth/{provider}", s.startAuth)
	r.Get("/auth/{provider}/callback", s.getAuthCallback)
	r.Get("/logout", s.logout)
	r.Get("/users", handleGetUsers)
	r.Get("/getSessions", handleGetUserSessions)
	r.Get("/sessionAnalysis", handleGetAnalysis)
	r.Post("/createSession", handleCreateSession)
	r.Post("/processCoords", s.processCoordsHandler)
	r.Post("/postProcessing", s.handlePostAnalysis)
	r.Post("/updateMinMaxVar", handleUpdateMinMaxVar)
	r.Get("/getMinMaxVar", handleGetMinMaxVar)
	r.Post("/updateMinMaxAcc", handleUpdateMinMaxAcc)
	r.Get("/getMinMaxAcc", handleGetMinMaxAcc)
	r.Post("/updateSessionAnalysis", handleInsertAnalysis)
	r.Post("/deleteSession", handleDeleteSession)
	r.Post("/updateSensitivity", handleUpdateSensitivity)
	r.Get("/getSensitivity", handleGetSensitivity)
	r.Post("/setMinMax", handleSetMinMax)
	r.Post("/updateMinMaxSetting", handleUpdateMinMaxSetting)
	r.Post("/updateNormalization", handleUpdateNormalization)
	r.Post("/updateGraphing", handleUpdateGraphing)
	r.Get("/getUserSettings", handleGetUserSettings)

	return r
}

// handleUpdateMinMaxSetting updates the min and max values in the database.
func handleUpdateMinMaxSetting(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	// Retrieve token from cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	// Get email associated with the token
	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	// Get user ID from email
	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Parse request body
	var requestData struct {
		MinMax bool `json:"minMax"`
	}
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Update Min/Max setting in the database
	err = dbService.UpdateMinMaxSetting(userID, requestData.MinMax)
	if err != nil {
		http.Error(w, "Failed to update Min/Max setting", http.StatusInternalServerError)
		return
	}

	// Success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Min/Max setting updated successfully"}`))
}

func handleUpdateGraphing(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	// Retrieve token from cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	// Get email associated with the token
	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	// Get user ID from email
	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Parse request body
	var requestData struct {
		Plotting bool `json:"plotting"`
	}
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Update Min/Max setting in the database
	err = dbService.UpdateGraphing(userID, requestData.Plotting)
	if err != nil {
		http.Error(w, "Failed to update graphing setting", http.StatusInternalServerError)
		return
	}

	// Success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Graphing setting updated successfully"}`))
}

func handleUpdateNormalization(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	// Retrieve token from cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	// Get email associated with the token
	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	// Get user ID from email
	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Parse request body
	var requestData struct {
		Normalization bool `json:"normalization"`
	}
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Update normalization setting in database
	err = dbService.UpdateMinMaxSetting(userID, requestData.Normalization)
	if err != nil {
		http.Error(w, "Failed to update normalization", http.StatusInternalServerError)
		return
	}

	// Success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Normalization updated successfully"}`))
}

func handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	var requestData struct {
		SessionID int `json:"session_id"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	err = dbService.DeleteSession(requestData.SessionID)
	if err != nil {
		http.Error(w, "Failed to delete session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Session deleted successfully"}`))
}

func handleGetUserSettings(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	plotting, affine, minMax, sensitivity, err := dbService.GetUserSettings(userID)
	if err != nil {
		http.Error(w, "Failed to retrieve settings", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"plotting":    plotting,
		"affine":      affine,
		"min_max":     minMax,
		"sensitivity": sensitivity,
	})
}

func (s *Server) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{"message": "Hello World"}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("error handling JSON marshal. Err: %v", err)
	}
	_, _ = w.Write(jsonResp)
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	jsonResp, _ := json.Marshal(s.db.Health())
	_, _ = w.Write(jsonResp)
}

func (s *Server) getAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	r = r.WithContext(context.WithValue(r.Context(), "provider", provider))

	// Complete the OAuth flow
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, "Could not complete authentication: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Debug: Print user details
	fmt.Printf("Authenticated user: %+v\n", user)

	dbService := database.New()

	// Check if the user exists
	exists, err := dbService.UserExists(user.Email)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if !exists {
		// Insert the OAuth user into the database
		_, err := dbService.InsertUser(user.Email, "")
		if err != nil {
			http.Error(w, "Failed to log OAuth user into the database", http.StatusInternalServerError)
			return
		}
	}

	// Generate JWT for OAuth user
	claims := &jwt.RegisteredClaims{
		Subject:   user.Email,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Insert the JWT token into the database
	err = dbService.InsertUserToken(user.Email, signedToken)
	if err != nil {
		http.Error(w, "Failed to insert token into the database", http.StatusInternalServerError)
		return
	}

	// Set the JWT token in a secure, HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    signedToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Set to true in production
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to the frontend dashboard
	http.Redirect(w, r, os.Getenv("CLIENT_URL")+"/dashboard", http.StatusFound)
}

func jsonErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	dbService := database.New()

	exists, err := dbService.UserExists(req.Email)
	if err != nil {
		jsonErrorResponse(w, "Database error", http.StatusInternalServerError)
		return
	}

	if !exists {
		jsonErrorResponse(w, "User does not exist", http.StatusNotFound)
		return
	}

	storedHashedPassword, err := dbService.GetUserPassword(req.Email)
	if err != nil {
		jsonErrorResponse(w, "Database error", http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(req.Password))
	if err != nil {
		jsonErrorResponse(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	claims := &jwt.RegisteredClaims{
		Subject:   req.Email,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(168 * time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		jsonErrorResponse(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Insert the JWT token into the database
	err = dbService.InsertUserToken(req.Email, signedToken)
	if err != nil {
		jsonErrorResponse(w, "Failed to insert token into the database", http.StatusInternalServerError)
		return
	}

	// Set the JWT token in a secure, HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    signedToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Set to true in production
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
	})

	// Send response with JWT
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Login successful",
		// "token":   signedToken,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	dbService := database.New()

	exists, err := dbService.UserExists(req.Email)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Insert new user with hashed password
	userID, err := dbService.InsertUser(req.Email, string(hashedPassword))
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	err = dbService.InsertSettings(userID, 4.5e-07, 0.00013, 0.3, 10.0)
	if err != nil {
		jsonErrorResponse(w, "Failed to create settings for user", http.StatusInternalServerError)
		return
	}

	// Generate JWT token
	claims := &jwt.RegisteredClaims{
		Subject:   req.Email,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(168 * time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		jsonErrorResponse(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Insert the JWT token into the database
	err = dbService.InsertUserToken(req.Email, signedToken)
	if err != nil {
		jsonErrorResponse(w, "Failed to insert token into the database", http.StatusInternalServerError)
		return
	}

	// Set the JWT token in a secure, HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    signedToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Set to true in production
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User created successfully",
		"userID":  userID,
	})
}

func handleGetUsers(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	users, err := dbService.GetAllUsers()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	usersJSON, err := json.Marshal(users)
	if err != nil {
		http.Error(w, "Failed to encode users to JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(usersJSON)
}

func (s *Server) startAuth(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	r = r.WithContext(context.WithValue(context.Background(), "provider", provider))
	gothic.BeginAuthHandler(w, r)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err == nil && cookie.Value != "" {
		dbService := database.New()
		err := dbService.RemoveUserToken(cookie.Value)
		if err != nil {
			log.Printf("Failed to remove token from database: %v", err)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
	}

	err = gothic.Logout(w, r)
	if err != nil {
		fmt.Println("No OAuth session to clear: ", err)
	}

	http.Redirect(w, r, os.Getenv("CLIENT_URL")+"/", http.StatusFound)
}

type Session struct {
	StartTime string  `json:"start_time"`
	EndTime   string  `json:"end_time"`
	Min       float64 `json:"min"`
	Max       float64 `json:"max"`
	CreatedAt string  `json:"created_at"`
}

type Analysis struct {
	SessionID int     `json:"session_id"`
	Timestamp float64 `json:"timestamp"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Prob      float64 `json:"prob"`
	CreatedAt string  `json:"created_at"`
}

func handleGetAnalysis(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	var requestData struct {
		SessionID int `json:"session_id"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	analysisData, err := dbService.GetSessionAnalysis(requestData.SessionID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	analysisJSON, err := json.Marshal(analysisData)
	if err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(analysisJSON)
}

func handleGetUserSessions(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	// Get the token from the cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		fmt.Println("Error getting cookie: ", err) // Log the error
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	// Validate token
	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		fmt.Println("Error or invalid token: ", err) // Log the error
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	// Get user ID by email
	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		fmt.Println("Error getting user ID: ", err) // Log the error
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Fetch user sessions
	sessions, err := dbService.GetUserSessions(userID)
	if err != nil {
		fmt.Println("Error fetching user sessions: ", err) // Log the error
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Marshal sessions to JSON
	sessionsJSON, err := json.Marshal(sessions)
	if err != nil {
		fmt.Println("Error encoding sessions to JSON: ", err) // Log the error
		http.Error(w, "Failed to encode sessions to JSON", http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(sessionsJSON)
}

func handleCreateSession(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	// Retrieve token from cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		fmt.Println("CreateSession Error: Missing token")
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	// Validate token and get user email
	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		fmt.Println("CreateSession Error: Invalid token or failed to get user", err)
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	// Get user ID from email
	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		fmt.Println("CreateSession Error: User not found", err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Log the user ID for debugging
	fmt.Printf("User ID for %s: %d\n", email, userID)

	// Decode request body
	var requestData struct {
		Name      string  `json:"name"`
		StartTime string  `json:"start_time"`
		EndTime   string  `json:"end_time"`
		VMin      float64 `json:"v_min"`
		VMax      float64 `json:"v_max"`
		AMin      float64 `json:"a_min"`
		AMax      float64 `json:"a_max"`
	}

	fmt.Println("Request Data: ", requestData)

	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		fmt.Println("CreateSession Error: Invalid request body", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Log the decoded requestData for debugging
	fmt.Printf("Received request data: %+v\n", requestData)

	// Insert session into database and get the session ID
	sessionID, err := dbService.CreateSession(requestData.Name, userID, requestData.StartTime, requestData.EndTime, requestData.VMin, requestData.VMax, requestData.AMin, requestData.AMax)
	if err != nil {
		fmt.Println("CreateSession Error: Failed to create session", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	log.Println("Session created successfully for user:", userID)

	// Return session ID in the response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"message": "Session created successfully", "sessionId": "%d"}`, sessionID)))
}

type AnalysisState struct {
	LastX, LastY, LastTime, LastVelocity float64
	Initialized                          bool
}

func clipAndScale(value, min, max float64) float64 {
	valAbs := math.Abs(value)
	clipped := math.Min(math.Max(valAbs, min), max)
	return 0.01 + 0.95*(clipped/max)
}

func singleUpdate(state *AnalysisState, t, x, y, varMin, varMax, accMin, accMax float64) (float64, float64, float64) {
	if !state.Initialized {
		state.LastX, state.LastY, state.LastTime, state.LastVelocity = x, y, t, 0.0
		state.Initialized = true
		return 0.0, 0.0, 0.05
	}

	dt := t - state.LastTime
	if dt <= 0.0 {
		return 0.0, 0.0, 0.05
	}
	dx := x - state.LastX
	dy := y - state.LastY
	variance := dx*dx + dy*dy
	velocity := math.Sqrt(variance) / dt
	acceleration := (velocity - state.LastVelocity) / dt

	varianceNorm := clipAndScale(variance, varMin, varMax)
	accelerationNorm := clipAndScale(acceleration, accMin, accMax)
	probability := (varianceNorm + accelerationNorm) / 2.0

	state.LastX, state.LastY, state.LastTime, state.LastVelocity = x, y, t, velocity

	return varianceNorm, accelerationNorm, probability
}

func (s *Server) processCoordsHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Timestamp   float64     `json:"timestamp"`
		Coordinates [][]float64 `json:"coordinates"`
	}

	cookie, err := r.Cookie("token")
	if err != nil {
		log.Printf("Error reading cookie: %v", err)
		http.Error(w, "Token cookie not found", http.StatusUnauthorized)
		return
	}

	token := cookie.Value
	dbService := database.New()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("JSON decode error: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	email, valid, err := dbService.GetUserByToken(token)
	if err != nil {
		log.Printf("Error getting user by token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !valid {
		log.Printf("Invalid token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	log.Printf("Token belongs to user: %s", email)

	state := &AnalysisState{}
	var results []map[string]float64

	for _, coord := range req.Coordinates {
		if len(coord) != 2 {
			continue
		}
		vn, an, prob := singleUpdate(state, req.Timestamp, coord[0], coord[1], 4.5e-07, 0.00013, 0.3, 10.0)
		results = append(results, map[string]float64{
			"variance":     vn,
			"acceleration": an,
			"probability":  prob,
		})
	}

	respData, err := json.Marshal(results)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		http.Error(w, "Failed to process data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respData)
}

func (s *Server) handlePostAnalysis(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Timestamp   float64     `json:"timestamp"`
		Coordinates [][]float64 `json:"coordinates"`
	}

	cookie, err := r.Cookie("token")
	if err != nil {
		log.Printf("Error reading cookie: %v", err)
		http.Error(w, "Token cookie not found", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	dbService := database.New()
	email, valid, err := dbService.GetUserByToken(token)
	if err != nil {
		log.Printf("Error getting user by token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !valid {
		log.Printf("Invalid token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	varMin, varMax, err := dbService.GetUserMinMaxVar(userID)
	if err != nil {
		http.Error(w, "Failed to retrieve variance min/max", http.StatusInternalServerError)
		return
	}

	accMin, accMax, err := dbService.GetUserMinMaxAcc(userID)
	if err != nil {
		http.Error(w, "Failed to retrieve acceleration min/max", http.StatusInternalServerError)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("JSON decode error: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	state := &AnalysisState{}
	var results []map[string]float64

	for _, coord := range req.Coordinates {
		if len(coord) != 2 {
			continue
		}
		vn, an, prob := singleUpdate(state, req.Timestamp, coord[0], coord[1], varMin, varMax, accMin, accMax)
		results = append(results, map[string]float64{
			"variance":     vn,
			"acceleration": an,
			"probability":  prob,
		})
	}

	respData, err := json.Marshal(results)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		http.Error(w, "Failed to process data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respData)
}

func handleInsertAnalysis(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	var analysisEntries []database.AnalysisData

	err := json.NewDecoder(r.Body).Decode(&analysisEntries)
	if err != nil {
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	if len(analysisEntries) == 0 {
		http.Error(w, "No analysis data provided", http.StatusBadRequest)
		return
	}

	err = dbService.InsertAnalysis(analysisEntries)
	if err != nil {
		http.Error(w, "Failed to insert analysis data", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message": "Analysis data inserted successfully"}`))
}

func handleUpdateSensitivity(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var requestData struct {
		Sensitivity float64 `json:"sensitivity"`
	}
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = dbService.UpdateSensitivity(userID, requestData.Sensitivity)
	if err != nil {
		http.Error(w, "Failed to update sensitivity", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Sensitivity updated successfully"}`))
}

func handleGetSensitivity(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sensitivity, err := dbService.GetSensitivity(userID)
	if err != nil {
		http.Error(w, "Failed to retrieve sensitivity", http.StatusInternalServerError)
		return
	}

	response := map[string]float64{"sensitivity": sensitivity}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleUpdateMinMaxVar(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	err = dbService.UpdateUserMinMaxVar(userID)
	if err != nil {
		http.Error(w, "Failed to update variance min/max settings", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Variance min/max values updated successfully"})
}

func handleGetMinMaxVar(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	varMin, varMax, err := dbService.GetUserMinMaxVar(userID)
	if err != nil {
		http.Error(w, "Failed to retrieve variance min/max settings", http.StatusInternalServerError)
		return
	}

	response := map[string]float64{
		"var_min": varMin,
		"var_max": varMax,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleUpdateMinMaxAcc(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	err = dbService.UpdateUserMinMaxAcc(userID)
	if err != nil {
		http.Error(w, "Failed to update acceleration min/max settings", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Acceleration min/max values updated successfully"})
}

func handleGetMinMaxAcc(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	accMin, accMax, err := dbService.GetUserMinMaxAcc(userID)
	if err != nil {
		http.Error(w, "Failed to retrieve acceleration min/max settings", http.StatusInternalServerError)
		return
	}

	response := map[string]float64{
		"acc_min": accMin,
		"acc_max": accMax,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleSetMinMax(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return
	}
	token := cookie.Value

	email, valid, err := dbService.GetUserByToken(token)
	if err != nil || !valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := dbService.GetUserIDByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var requestBody struct {
		MinMax bool `json:"min_max"`
	}
	err = json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = dbService.UpdateMinMaxSetting(userID, requestBody.MinMax)
	if err != nil {
		http.Error(w, "Failed to update min_max setting", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Settings updated successfully"})
}
