package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"fmt"
	"time"

	"DETECT.go/internal/database"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/coder/websocket"

	"github.com/markbates/goth/gothic"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/", s.HelloWorldHandler)

	r.Get("/health", s.healthHandler)

	r.Get("/websocket", s.websocketHandler)

	r.Post("/login", s.handleLogin)

	r.Post("/register", s.handleRegister)

	r.Get("/auth/{provider}", s.startAuth)

	r.Get("/auth/{provider}/callback", s.getAuthCallback)

	r.Get("/logout", s.logout)

	r.Get("/users", handleGetUsers)

	return r
}

func (s *Server) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	resp := make(map[string]string)
	resp["message"] = "Hello World"

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
	// Retrieve the provider from the URL parameters
	provider := chi.URLParam(r, "provider")

	// Set the provider in the context
	r = r.WithContext(context.WithValue(r.Context(), "provider", provider))

	// Debug: Log session retrieval
	session, err := gothic.Store.Get(r, "gothic-session")
	if err != nil {
		fmt.Println("Error retrieving session:", err)
	} else {
		fmt.Println("Session retrieved successfully:", session.Values)
	}

	// Complete the OAuth flow
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		// Log the error and return it to the user for debugging
		fmt.Println("Error completing user authentication:", err)
		http.Error(w, "Could not complete authentication: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Debug: Print user details
	fmt.Printf("Authenticated user: %+v\n", user)

	// Redirect to the frontend dashboard
	http.Redirect(w, r, "http://localhost:4321/dashboard", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	// Check if the user is logged in via a traditional session
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		// Clear the traditional session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
	}

	// Attempt to clear the OAuth session (if any)
	err = gothic.Logout(w, r)
	if err != nil {
		// Ignore error if no OAuth session exists
		fmt.Println("No OAuth session to clear: ", err)
	}

	// Redirect to the frontend login page or confirmation page
	http.Redirect(w, r, "http://localhost:4321/", http.StatusFound)
}

func (s *Server) startAuth(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	r = r.WithContext(context.WithValue(context.Background(), "provider", provider))
	gothic.BeginAuthHandler(w, r)
}

func (s *Server) websocketHandler(w http.ResponseWriter, r *http.Request) {
	socket, err := websocket.Accept(w, r, nil)

	if err != nil {
		log.Printf("could not open websocket: %v", err)
		_, _ = w.Write([]byte("could not open websocket"))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer socket.Close(websocket.StatusGoingAway, "server closing websocket")

	ctx := r.Context()
	socketCtx := socket.CloseRead(ctx)

	for {
		payload := fmt.Sprintf("server timestamp: %d", time.Now().UnixNano())
		err := socket.Write(socketCtx, websocket.MessageText, []byte(payload))
		if err != nil {
			break
		}
		time.Sleep(time.Second * 2)
	}
}

// handleRegister handles the registration of a user.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Parse JSON body
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

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(fmt.Sprintf("User created with ID: %d", userID)))
}

// handleGetUsers handles the retrieval of all registered users.
func handleGetUsers(w http.ResponseWriter, r *http.Request) {
    // Initialize database service
    dbService := database.New()

    // Get all users
    users, err := dbService.GetAllUsers()
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    // Convert users map to JSON
    usersJSON, err := json.Marshal(users)
    if err != nil {
        http.Error(w, "Failed to encode users to JSON", http.StatusInternalServerError)
        return
    }

    // Return JSON response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write(usersJSON)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    // Parse request body
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"` 
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

	dbService := database.New()

	exists, err := dbService.UserExists(req.Email)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if !exists {
		http.Error(w, "User does not exist", http.StatusNotFound)
		return
	}

	// Verify the password using bcrypt
	storedHashedPassword, err := dbService.GetUserPassword(req.Email)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(req.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful"))
}