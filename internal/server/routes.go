package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"DETECT.go/internal/database"
	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/markbates/goth/gothic"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

/*
! Send the JWT token as a cookie to the client on traditional login/register
*/


func init() {
	// Load .env file
	// err := godotenv.Load()
	// if err != nil {
	// 	log.Fatalf("Error loading .env file")
	// }

	// Read the secret from .env
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatalf("JWT_SECRET is not set in the .env file")
	}

	jwtSecret = []byte(secret)
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
		http.Error(w, "Could not complete authentication: "+ err.Error(), http.StatusInternalServerError)
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
        SameSite: http.SameSiteNoneMode,
    })

	// Redirect to the frontend dashboard
	http.Redirect(w, r, os.Getenv("CLIENT_URL") + "/dashboard", http.StatusFound)
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

	http.Redirect(w, r, os.Getenv("CLIENT_URL") + "/", http.StatusFound)
}
