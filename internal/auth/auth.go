package auth

import (
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

const (
    // Use a strong, random key in production
    key = "secureRandomKey12345" 
    // A session is valid for 7 days
    MaxAge = 60 * 60 * 24 * 7
)

func NewAuth() {
    googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
    googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
    serverURL := os.Getenv("SERVER_URL")
    isProd := os.Getenv("IS_PROD") == "true"

    // Create a more secure cookie store with explicit settings
    store := sessions.NewCookieStore([]byte(key))
    store.MaxAge(MaxAge)
    store.Options.Path = "/"
    store.Options.HttpOnly = true
    store.Options.Secure = isProd
    
    // Always use SameSiteLaxMode for OAuth flows
    store.Options.SameSite = http.SameSiteLaxMode
    
    gothic.Store = store
    // gothic.SessionName = "gothic_session"
    
    callbackURL := serverURL + "/auth/google/callback"
    
    // Register only the Google provider
    goth.UseProviders(
        google.New(googleClientID, googleClientSecret, callbackURL, "email", "profile"),
    )
    
}