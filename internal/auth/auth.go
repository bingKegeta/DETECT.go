package auth

import (
	"os"

	"net/http"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

const (
	key = "secureRandomKey12345"
	// A session is valid for 7 days
	MaxAge = 60 * 60 * 24 * 7
	isProd = false
)

func NewAuth() {
	environment := os.Getenv("SERVER_URL")
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(MaxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = isProd
	store.Options.SameSite = http.SameSiteLaxMode

	gothic.Store = store

	goth.UseProviders(
		google.New(googleClientID, googleClientSecret, environment + "/auth/google/callback", "email", "profile"),
	)

}
