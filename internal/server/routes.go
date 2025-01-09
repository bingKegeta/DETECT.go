package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"fmt"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/coder/websocket"

	"github.com/markbates/goth/gothic"
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

	r.Get("/auth/{provider}", s.startAuth)

	r.Get("/auth/{provider}/callback", s.getAuthCallback)

	r.Get("/logout", s.logout)

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
