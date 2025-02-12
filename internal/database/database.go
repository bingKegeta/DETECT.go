package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/joho/godotenv/autoload"
)

// Service represents a service that interacts with a database.
type Service interface {
	// Health returns a map of health status information.
	// The keys and values in the map are service-specific.
	Health() map[string]string

	// Close terminates the database connection.
	// It returns an error if the connection cannot be closed.
	Close() error

	// UserExists checks if a user exists by username.
	UserExists(username string) (bool, error)

	// InsertUser inserts a new user into the database.
	InsertUser(username, password string) (int, error)

	// GetAllUsers returns the IDs and emails of all registered users.
	GetAllUsers() (map[int]string, error)

	// VerifyUser verifies a user's credentials.
	VerifyUser(email, password string) (bool, error)

	// GetUserPassword retrieves the hashed password for a given email.
	GetUserPassword(email string) (string, error)

	// InsertUserToken inserts token upon login
	InsertUserToken(email, token string) error

	// RemoveUserToken removes the JWT token for a given email.
	RemoveUserToken(token string) error

	GetUserSessions(userID int) ([]Session, error)

	GetSessionAnalysis(sessionID int) ([]Analysis, error)

	GetUserIDByEmail(email string) (int, error)

	CreateSession(userID int, startTime, endTime string, min, max float64) error
}

type service struct {
	db *sql.DB
}

var (
	database   = os.Getenv("DB_DATABASE")
	password   = os.Getenv("DB_PASSWORD")
	username   = os.Getenv("DB_USERNAME")
	port       = os.Getenv("DB_PORT")
	host       = os.Getenv("DB_HOST")
	schema     = os.Getenv("DB_SCHEMA")
	dbInstance *service
)

func New() Service {
	// Reuse Connection
	if dbInstance != nil {
		return dbInstance
	}

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&search_path=%s", username, password, host, port, database, schema)
	db, err := sql.Open("pgx", connStr)
	if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }

	// Ping the database to ensure the connection is established
    err = db.Ping()
    if err != nil {
        log.Fatalf("Failed to ping database: %v", err)
    }

	dbInstance = &service{
		db: db,
	}
	return dbInstance
}

// Health checks the health of the database connection by pinging the database.
// It returns a map with keys indicating various health statistics.
func (s *service) Health() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := make(map[string]string)

	// Ping the database
	err := s.db.PingContext(ctx)
	if err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("db down: %v", err)
		log.Fatalf("db down: %v", err) // Log the error and terminate the program
		return stats
	}

	// Database is up, add more statistics
	stats["status"] = "up"
	stats["message"] = "It's healthy"

	// Get database stats (like open connections, in use, idle, etc.)
	dbStats := s.db.Stats()
	stats["open_connections"] = strconv.Itoa(dbStats.OpenConnections)
	stats["in_use"] = strconv.Itoa(dbStats.InUse)
	stats["idle"] = strconv.Itoa(dbStats.Idle)
	stats["wait_count"] = strconv.FormatInt(dbStats.WaitCount, 10)
	stats["wait_duration"] = dbStats.WaitDuration.String()
	stats["max_idle_closed"] = strconv.FormatInt(dbStats.MaxIdleClosed, 10)
	stats["max_lifetime_closed"] = strconv.FormatInt(dbStats.MaxLifetimeClosed, 10)

	// Evaluate stats to provide a health message
	if dbStats.OpenConnections > 40 { // Assuming 50 is the max for this example
		stats["message"] = "The database is experiencing heavy load."
	}

	if dbStats.WaitCount > 1000 {
		stats["message"] = "The database has a high number of wait events, indicating potential bottlenecks."
	}

	if dbStats.MaxIdleClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many idle connections are being closed, consider revising the connection pool settings."
	}

	if dbStats.MaxLifetimeClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many connections are being closed due to max lifetime, consider increasing max lifetime or revising the connection usage pattern."
	}

	return stats
}

// Close closes the database connection.
// It logs a message indicating the disconnection from the specific database.
// If the connection is successfully closed, it returns nil.
// If an error occurs while closing the connection, it returns the error.
func (s *service) Close() error {
	log.Printf("Disconnected from database: %s", database)
	return s.db.Close()
}

// Check if a user exists by email
func (s *service) UserExists(email string) (bool, error) {
    var exists bool
    query := "SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)"
    err := s.db.QueryRow(query, email).Scan(&exists)
    if err != nil {
        return false, err
    }
    return exists, nil
}

// Insert a new user into the database
func (s *service) InsertUser(email, password string) (int, error) {
    var userID int
    query := "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id"
    err := s.db.QueryRow(query, email, password).Scan(&userID)
    if err != nil {
        return 0, err
    }
    return userID, nil
}

// GetAllUsers returns the IDs and emails of all registered users.
func (s *service) GetAllUsers() (map[int]string, error) {
    users := make(map[int]string)
    query := "SELECT id, email FROM users"
    rows, err := s.db.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    for rows.Next() {
        var id int
        var email string
        if err := rows.Scan(&id, &email); err != nil {
            return nil, err
        }
        users[id] = email
    }

    if err := rows.Err(); err != nil {
        return nil, err
    }

    return users, nil
}

func (s *service) VerifyUser(email, password string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 AND password=$2)"
	var exists bool
	err := s.db.QueryRow(query, email, password).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// GetUserPassword retrieves the hashed password for a given email.
func (s *service) GetUserPassword(email string) (string, error) {
    var hashedPassword string
    query := "SELECT password FROM users WHERE email = $1"
    err := s.db.QueryRow(query, email).Scan(&hashedPassword)
    if err != nil {
        if err == sql.ErrNoRows {
            return "", fmt.Errorf("user not found")
        }
        return "", err
    }
    return hashedPassword, nil
}

// InsertUserToken inserts the JWT token and creation timestamp for the user.
func (s *service) InsertUserToken(email, token string) error {
    query := "UPDATE users SET auth_token=$1, auth_token_created_at=NOW() WHERE email=$2"
    _, err := s.db.Exec(query, token, email)
    return err
}

// RemoveUserToken removes the JWT token for a given email.
func (s *service) RemoveUserToken(token string) error {
    query := "UPDATE users SET auth_token=NULL, auth_token_created_at=NULL WHERE auth_token=$1"
    _, err := s.db.Exec(query, token)
    return err
}

type Session struct {
	UserID    int
	StartTime string
	EndTime   string
	Min       float64
	Max       float64
	CreatedAt string
}

type Analysis struct {
	SessionID int     `json:"session_id"`
	Timestamp float64 `json:"timestamp"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Prob      float64 `json:"prob"`
	CreatedAt string  `json:"created_at"`
}

func (s *service) GetUserSessions(userID int) ([]Session, error) {
	var sessions []Session

	query := `SELECT user_id, start_time, end_time, min, max, created_at FROM session WHERE user_id = $1 ORDER BY start_time DESC`
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ses Session
		err := rows.Scan(&ses.UserID, &ses.StartTime, &ses.EndTime, &ses.Min, &ses.Max, &ses.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %v", err)
		}
		sessions = append(sessions, ses)
	}

	return sessions, nil
}

func (s *service) GetSessionAnalysis(sessionID int) ([]Analysis, error) {
	var analysisData []Analysis

	query := `SELECT session_id, timestamp, x, y, prob, created_at FROM analysis WHERE session_id = $1 ORDER BY timestamp ASC`
	rows, err := s.db.Query(query, sessionID)
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var analysis Analysis
		err := rows.Scan(&analysis.SessionID, &analysis.Timestamp, &analysis.X, &analysis.Y, &analysis.Prob, &analysis.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %v", err)
		}
		analysisData = append(analysisData, analysis)
	}

	return analysisData, nil
}

func (s *service) GetUserIDByEmail(email string) (int, error) {
	var userID int

	query := `SELECT id FROM Users WHERE email = $1`
	row := s.db.QueryRow(query, email)

	err := row.Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("user not found")
		}
		return 0, fmt.Errorf("error querying database: %v", err)
	}

	return userID, nil
}

func (s *service) CreateSession(userID int, startTime, endTime string, min, max float64) error {
	query := `INSERT INTO session (user_id, start_time, end_time, min, max) VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.Exec(query, userID, startTime, endTime, min, max)
	if err != nil {
		return fmt.Errorf("error inserting session: %v", err)
	}

	return nil
}
