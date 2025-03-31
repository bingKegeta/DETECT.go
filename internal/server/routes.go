package server

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"DETECT.go/internal/database"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	"github.com/markbates/goth/gothic"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

const (
	maxConnectionsPerUser = 5
	messageRateLimit      = 100
	burstLimit            = 20
	writeWait             = 10 * time.Second
	pongWait              = 60 * time.Second
	pingPeriod            = (pongWait * 9) / 10
)

// UserTracker manages all user-specific tracking data
type UserTracker struct {
	mu    sync.Mutex
	users map[string]*UserData
}

// NewUserTracker creates a new thread-safe user tracker
func NewUserTracker() *UserTracker {
	return &UserTracker{
		users: make(map[string]*UserData),
	}
}

// GetUserData safely retrieves or creates user data
func (ut *UserTracker) GetUserData(userID string) *UserData {
	ut.mu.Lock()
	defer ut.mu.Unlock()

	if data, exists := ut.users[userID]; exists {
		return data
	}

	data := &UserData{
		initialized: false,
	}
	ut.users[userID] = data
	return data
}

// RemoveUser safely removes user data
func (ut *UserTracker) RemoveUser(userID string) {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	delete(ut.users, userID)
}

// UserData holds tracking data for a single user
type UserData struct {
	sync.Mutex
	lastX, lastY float64
	lastTime     float64
	lastVelocity float64
	initialized  bool
}

// WebSocketConnection structure
type WebSocketConnection struct {
	conn      *websocket.Conn
	mu        sync.Mutex
	done      chan struct{}
	limiter   *rate.Limiter
	userID    string
	createdAt time.Time
}

// Metrics structure for monitoring
type Metrics struct {
	TotalConnections  int
	ActiveUsers       int
	MessagesProcessed int64
}

var (
	userTracker     = NewUserTracker()
	connections     sync.Map // Stores WebSocket connections per user
	connectionCount sync.Map // Stores connection counts per user
	metrics         Metrics
	metricsMutex    sync.Mutex
	globalLimiter   = rate.NewLimiter(messageRateLimit, burstLimit)
	jwtSecret       = []byte(os.Getenv("JWT_SECRET"))
)

func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id is required", http.StatusUnauthorized)
		return
	}

	if count, ok := connectionCount.Load(userID); ok && count.(int) >= maxConnectionsPerUser {
		http.Error(w, "maximum connections reached", http.StatusTooManyRequests)
		return
	}

	upgrader := &websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		HandshakeTimeout: 5 * time.Second,
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade WebSocket connection for user %s: %v", userID, err)
		http.Error(w, "Failed to upgrade connection", http.StatusInternalServerError)
		return
	}

	wsConn := &WebSocketConnection{
		conn:      conn,
		done:      make(chan struct{}),
		limiter:   rate.NewLimiter(messageRateLimit, burstLimit),
		userID:    userID,
		createdAt: time.Now(),
	}

	conns, _ := connections.LoadOrStore(userID, &sync.Map{})
	userConns := conns.(*sync.Map)
	userConns.Store(wsConn, struct{}{})

	updateConnectionCount(userID, 1)
	updateMetrics(1, 0)

	log.Printf("User %s connected. Total connections: %d", userID, userMapSize(userConns))

	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	go wsConn.writePump()
	go wsConn.readPump()
}

func (c *WebSocketConnection) readPump() {
	defer c.closeConnection()

	for {
		select {
		case <-c.done:
			return
		default:
			messageType, msg, err := c.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("User %s unexpected disconnect: %v", c.userID, err)
				}
				return
			}

			if !c.limiter.Allow() {
				log.Printf("User %s exceeded rate limit", c.userID)
				c.sendError("rate limit exceeded")
				continue
			}

			go processGazeData(msg, c.userID, messageType, c)
		}
	}
}

func (c *WebSocketConnection) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.closeConnection()
	}()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.mu.Lock()
			if err := c.conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(writeWait)); err != nil {
				log.Printf("User %s ping failed: %v", c.userID, err)
				c.mu.Unlock()
				return
			}
			c.mu.Unlock()
		}
	}
}

func (c *WebSocketConnection) closeConnection() {
	close(c.done)

	if conns, ok := connections.Load(c.userID); ok {
		userConns := conns.(*sync.Map)
		userConns.Delete(c)

		updateConnectionCount(c.userID, -1)

		if userMapSize(userConns) == 0 {
			connections.Delete(c.userID)
			userTracker.RemoveUser(c.userID)
			log.Printf("User %s fully disconnected, cleaning up state.", c.userID)
		}
	}

	updateMetrics(-1, 0)
	c.conn.Close()
	log.Printf("User %s WebSocket closed (duration: %v)", c.userID, time.Since(c.createdAt))
}

func (c *WebSocketConnection) sendError(message string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	errMsg := struct {
		Error string `json:"error"`
	}{
		Error: message,
	}

	msg, _ := json.Marshal(errMsg)
	c.conn.WriteMessage(websocket.TextMessage, msg)
}

func processGazeData(message []byte, userID string, messageType int, sender *WebSocketConnection) {
	if !globalLimiter.Allow() {
		log.Printf("Global rate limit exceeded for user %s", userID)
		return
	}

	var gazeData struct {
		Time        float64 `json:"time"`
		X           float64 `json:"x"`
		Y           float64 `json:"y"`
		Sensitivity float64 `json:"sensitivity,omitempty"`
	}

	if err := json.Unmarshal(message, &gazeData); err != nil {
		log.Printf("User %s: Error parsing WebSocket message: %v", userID, err)
		return
	}

	variance, acceleration, probability := AnalyzeGazeData(userID, gazeData.Time, gazeData.X, gazeData.Y, gazeData.Sensitivity)

	analysisResponse := struct {
		Variance     float64 `json:"variance"`
		Acceleration float64 `json:"acceleration"`
		Probability  float64 `json:"probability"`
		Timestamp    int64   `json:"timestamp"`
	}{
		Variance:     variance,
		Acceleration: acceleration,
		Probability:  probability,
		Timestamp:    time.Now().UnixMilli(),
	}

	responseJSON, err := json.Marshal(analysisResponse)
	if err != nil {
		log.Printf("User %s: Error marshaling analysis response: %v", userID, err)
		return
	}

	updateMetrics(0, 1)

	if conns, ok := connections.Load(userID); ok {
		userConns := conns.(*sync.Map)

		userConns.Range(func(key, value interface{}) bool {
			wsConn := key.(*WebSocketConnection)

			if wsConn == sender {
				return true
			}

			select {
			case <-wsConn.done:
				return true
			default:
				wsConn.mu.Lock()
				defer wsConn.mu.Unlock()

				wsConn.conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := wsConn.conn.WriteMessage(messageType, responseJSON); err != nil {
					log.Printf("User %s: Error sending message: %v", userID, err)
					wsConn.conn.Close()
					userConns.Delete(wsConn)
					updateConnectionCount(userID, -1)
					updateMetrics(-1, 0)
				}
				return true
			}
		})
	}
}

func AnalyzeGazeData(userID string, time, x, y, sensitivity float64) (float64, float64, float64) {
	userData := userTracker.GetUserData(userID)
	userData.Lock()
	defer userData.Unlock()

	log.Printf("Processing user %s (initialized: %v)", userID, userData.initialized)

	if sensitivity < 0.75 || sensitivity > 1.25 || math.IsNaN(sensitivity) || math.IsInf(sensitivity, 0) {
		sensitivity = 1.0
	}

	if !userData.initialized {
		if time > 0 {
			userData.lastX = x
			userData.lastY = y
			userData.lastTime = time
			userData.initialized = true
			log.Printf("Initialized tracking for user %s", userID)
			return 0.0, 0.0, 0.05
		}
		return 0.0, 0.0, 0.05
	}

	if time < userData.lastTime {
		log.Printf("Time inconsistency for user %s. Resetting.", userID)
		userData.initialized = false
		return 0.0, 0.0, 0.05
	}

	dt := time - userData.lastTime
	if dt <= 0 {
		log.Printf("Invalid dt for user %s", userID)
		return 0.0, 0.0, 0.05
	}

	dx := x - userData.lastX
	dy := y - userData.lastY
	distance := math.Sqrt(dx*dx + dy*dy)
	velocity := distance / dt
	acceleration := 0.0
	if dt > 1e-6 {
		acceleration = (velocity - userData.lastVelocity) / dt
	}

	varianceNorm := ClipAndScale(distance*distance, 4.5e-7, 0.00013, 0.01, 0.95)
	accelNorm := ClipAndScale(acceleration, 0.3, 10.0, 0.01, 0.95)
	probability := math.Max(0.05, math.Min(1.0, (varianceNorm+accelNorm)/2.0*sensitivity))

	userData.lastX = x
	userData.lastY = y
	userData.lastTime = time
	userData.lastVelocity = velocity

	log.Printf("User %s - Variance: %.4f, Accel: %.4f, Prob: %.4f",
		userID, varianceNorm, accelNorm, probability)

	return varianceNorm, accelNorm, probability
}

func ClipAndScale(value, min, max, scaleMin, scaleMax float64) float64 {
	valAbs := math.Abs(value)
	clipped := math.Min(math.Max(valAbs, min), max)
	return scaleMin + (scaleMax-scaleMin)*(clipped/max)
}

func userMapSize(m *sync.Map) int {
	count := 0
	m.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

func updateConnectionCount(userID string, delta int) {
	count, _ := connectionCount.LoadOrStore(userID, 0)
	newCount := count.(int) + delta
	if newCount <= 0 {
		connectionCount.Delete(userID)
	} else {
		connectionCount.Store(userID, newCount)
	}
}

func updateMetrics(connDelta int, msgDelta int64) {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()

	metrics.TotalConnections += connDelta
	if connDelta > 0 {
		metrics.ActiveUsers = len(getActiveUsers())
	} else if connDelta < 0 {
		metrics.ActiveUsers = len(getActiveUsers())
	}
	metrics.MessagesProcessed += msgDelta
}

func getActiveUsers() []string {
	var users []string
	connections.Range(func(key, value interface{}) bool {
		users = append(users, key.(string))
		return true
	})
	return users
}

func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()

	json.NewEncoder(w).Encode(metrics)
}

func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	environment := os.Getenv("CLIENT_URL")
	isProd := os.Getenv("IS_PROD") == "true"
	if environment == "" {
		log.Fatalf("CLIENT_URL is not set in the .env file")
	}
	corsOptions := cors.Options{
		AllowedOrigins:   []string{environment, "https://accounts.google.com", "*.vercel.app"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}

	if !isProd {
		corsOptions.AllowedOrigins = []string{"*"} // Allow all origins in development
	}
	r.Use(cors.Handler(corsOptions))

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

	// Parse request body
	var requestData struct {
		UserID int  `json:"user_id"`
		MinMax bool `json:"minMax"`
	}
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Update Min/Max setting in the database
	err = dbService.UpdateMinMaxSetting(requestData.UserID, requestData.MinMax)
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

	// Parse request body
	var requestData struct {
		UserID   int  `json:"user_id"`
		Plotting bool `json:"plotting"`
	}
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Update Min/Max setting in the database
	err = dbService.UpdateGraphing(requestData.UserID, requestData.Plotting)
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

	// ! Not needed anymore
	// Retrieve token from cookie
	// cookie, err := r.Cookie("token")
	// if err != nil {
	// 	http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
	// 	return
	// }
	// token := cookie.Value

	// Get email associated with the token
	// email, valid, err := dbService.GetUserByToken(token)
	// if err != nil || !valid {
	// 	http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
	// 	return
	// }

	// // Get user ID from email
	// userID, err := dbService.GetUserIDByEmail(email)
	// if err != nil {
	// 	http.Error(w, "User not found", http.StatusNotFound)
	// 	return
	// }

	// Parse request body
	var requestData struct {
		UserID        int  `json:"user_id"`
		Normalization bool `json:"normalization"`
	}
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Update normalization setting in database
	err = dbService.UpdateNormalization(requestData.UserID, requestData.Normalization)
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
		UserID    int `json:"user_id"`
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

	userIDStr := r.URL.Query().Get("user_id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user id", http.StatusBadRequest)
		return
	}
	fmt.Println("Retrieved user ID from URL:", userID)

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
	fmt.Printf("Auth callback for provider: %s\n", provider)

	// Get the session to see if it exists in the callback
	session, _ := gothic.Store.Get(r, gothic.SessionName)
	fmt.Printf("Session in callback - Values: %v\n", session.Values)

	// Override GetProviderName just for this request
	gothic.GetProviderName = func(req *http.Request) (string, error) {
		return provider, nil
	}

	// Complete the OAuth flow
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		fmt.Printf("Auth error: %v\n", err)
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

	isProd := os.Getenv("IS_PROD") == "true"

	// Set the JWT token in a secure, HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    signedToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   isProd, // Set to true in production
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
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

	isProd := os.Getenv("IS_PROD") == "true"

	// Set the JWT token in a secure, HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    signedToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   isProd, // Set to true in production
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
	})

	userID, err := dbService.GetUserIDByEmail(req.Email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Send response with JWT
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Login successful",
		"isProd":  isProd,
		"userID":  userID,
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

	isProd := os.Getenv("IS_PROD") == "true"

	// Set the JWT token in a secure, HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    signedToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   isProd, // Set to true in production
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
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
	fmt.Printf("Starting auth for provider: %s\n", provider)

	// Create a modified request with the provider set correctly
	req := r.WithContext(r.Context())

	// Override GetProviderName just for this request
	gothic.GetProviderName = func(req *http.Request) (string, error) {
		return provider, nil
	}

	// Explicitly save a session with the provider name
	session, _ := gothic.Store.Get(r, gothic.SessionName)
	session.Values["provider"] = provider
	session.Save(r, w)

	gothic.BeginAuthHandler(w, req)
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
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

	response := Response{
		Success: true,
		Message: "Logged out successfully",
	}

	json.NewEncoder(w).Encode(response)
}

type Session struct {
	StartTime string  `json:"start_time"`
	EndTime   string  `json:"end_time"`
	Min       float64 `json:"min"`
	Max       float64 `json:"max"`
	CreatedAt string  `json:"created_at"`
}

type AnalysisData struct {
	SessionID int     `json:"session_id"`
	Timestamp float64 `json:"timestamp"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Prob      float64 `json:"prob"`
}

func handleGetAnalysis(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	sessionIDStr := r.URL.Query().Get("id")
	if sessionIDStr == "" {
		http.Error(w, "Missing session_id in URL", http.StatusBadRequest)
		return
	}

	sessionID, err := strconv.Atoi(sessionIDStr)
	if err != nil {
		http.Error(w, "Invalid session_id format", http.StatusBadRequest)
		return
	}

	analysisData, err := dbService.GetSessionAnalysis(sessionID)
	if err != nil {
		http.Error(w, "Failed to retrieve analysis data", http.StatusInternalServerError)
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

	userIDStr := r.URL.Query().Get("user_id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user id", http.StatusBadRequest)
		return
	}

	fmt.Println("Retrieved user ID from URL:", userID)

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

	// Decode request body
	var requestData struct {
		UserID    int     `json:"user_id"`
		Name      string  `json:"name"`
		StartTime string  `json:"start_time"`
		EndTime   string  `json:"end_time"`
		VMin      float64 `json:"v_min"`
		VMax      float64 `json:"v_max"`
		AMin      float64 `json:"a_min"`
		AMax      float64 `json:"a_max"`
	}

	fmt.Println("Request Data: ", requestData)

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		fmt.Println("CreateSession Error: Invalid request body", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Log the decoded requestData for debugging
	fmt.Printf("Received request data: %+v\n", requestData)
	/*
	   userID, err := strconv.Atoi(requestData.UserID)
	   if err != nil {
	       fmt.Println("Error:", err)
	       return
	   }*/

	// Insert session into database and get the session ID
	sessionID, err := dbService.CreateSession(requestData.Name, requestData.UserID, requestData.StartTime, requestData.EndTime, requestData.VMin, requestData.VMax, requestData.AMin, requestData.AMax)
	if err != nil {
		fmt.Println("CreateSession Error: Failed to create session", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	log.Println("Session created successfully for user:", requestData.UserID)

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
		UserID      int         `json:"user_id"`
		Timestamp   float64     `json:"timestamp"`
		Coordinates [][]float64 `json:"coordinates"`
	}

	//dbService := database.New()
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
		UserID      int         `json:"user_id"`
		Timestamp   float64     `json:"timestamp"`
		Coordinates [][]float64 `json:"coordinates"`
	}

	dbService := database.New()

	varMin, varMax, err := dbService.GetUserMinMaxVar(req.UserID)
	if err != nil {
		http.Error(w, "Failed to retrieve variance min/max", http.StatusInternalServerError)
		return
	}

	accMin, accMax, err := dbService.GetUserMinMaxAcc(req.UserID)
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

	var requestData struct {
		UserID      int     `json:"user_id"`
		Sensitivity float64 `json:"sensitivity"`
	}
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = dbService.UpdateSensitivity(requestData.UserID, requestData.Sensitivity)
	if err != nil {
		http.Error(w, "Failed to update sensitivity", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Sensitivity updated successfully"}`))
}

func handleGetSensitivity(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	userIDStr := r.URL.Query().Get("user_id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user id", http.StatusBadRequest)
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

	var requestBody struct {
		UserID int `json: "user_id"`
	}

	err := dbService.UpdateUserMinMaxVar(requestBody.UserID)
	if err != nil {
		http.Error(w, "Failed to update variance min/max settings", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Variance min/max values updated successfully"})
}

func handleGetMinMaxVar(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	userIDStr := r.URL.Query().Get("user_id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user id", http.StatusBadRequest)
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

	var requestBody struct {
		UserID int `json: "user_id"`
	}

	err := dbService.UpdateUserMinMaxAcc(requestBody.UserID)
	if err != nil {
		http.Error(w, "Failed to update acceleration min/max settings", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Acceleration min/max values updated successfully"})
}

func handleGetMinMaxAcc(w http.ResponseWriter, r *http.Request) {
	dbService := database.New()

	userIDStr := r.URL.Query().Get("user_id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user id", http.StatusBadRequest)
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

	var requestBody struct {
		UserID int  `json: "user_id"`
		MinMax bool `json:"min_max"`
	}
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = dbService.UpdateMinMaxSetting(requestBody.UserID, requestBody.MinMax)
	if err != nil {
		http.Error(w, "Failed to update min_max setting", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Settings updated successfully"})
}
