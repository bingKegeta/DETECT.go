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

	// GetUserByToken takes token input and helps validate the user on operation
	GetUserByToken(token string) (string, bool, error)

	GetUserIDByEmail(email string) (int, error)

	CreateSession(userID int, startTime, endTime string, min, max float64) error

	UpdateMinMax(userID int, min, max float64) error

	GetUserMinMax(userID int) (float64, float64, error)

	InsertAnalysis(sessionID int, timestamp, x, y, prob float64) error

	DeleteAnalysis(sessionID int) error

	DeleteSession(sessionID int) error

	UpdateSensitivity(userID int, newSensitivity float64) error

	GetSensitivity(userID int) (float64, error)

	AverageMinMax(userID int) error
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
	connection = os.Getenv("DB_CONNECTION")
	dbInstance *service
)

func New() Service {
	// Reuse Connection
	if dbInstance != nil {
		return dbInstance
	}

	// Check if DATABASE_URL is set (Railway usually provides it)
    connStr := os.Getenv("DATABASE_URL")
    if connStr == "" {
        // Fallback to constructing the connection string from individual environment variables
        username := os.Getenv("DB_USERNAME")
        password := os.Getenv("DB_PASSWORD")
        host := os.Getenv("DB_HOST")
        port := os.Getenv("DB_PORT")
        database := os.Getenv("DB_DATABASE")
        connStr = fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
            username, password, host, port, database)
    }
		
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

func (s *service) GetUserByToken(token string) (string, bool, error) {
	var email string

	query := `SELECT email FROM Users WHERE auth_token = $1`
	row:= s.db.QueryRow(query, token)

	err := row.Scan(&email)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, fmt.Errorf("error querying database: %v", err)
	}

	return email, true, nil
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

func (s *service) UpdateMinMax(userID int, min, max float64) error {
	query := `UPDATE settings SET min = $1, max = $2 WHERE userid = $3`
	result, err := s.db.Exec(query, min, max, userID)
	if err != nil {
		log.Printf("Database update error for user %d: %v", userID, err) // Debugging log
		return fmt.Errorf("error updating min/max: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error checking affected rows for user %d: %v", userID, err)
		return fmt.Errorf("error checking update status: %v", err)
	}

	if rowsAffected == 0 {
		insertQuery := `INSERT INTO settings (userid, min, max, plotting, affine, min_max) VALUES ($1, $2, $3, false, false, false)`
		_, err := s.db.Exec(insertQuery, userID, min, max)
		if err != nil {
			log.Printf("Database insert error for user %d: %v", userID, err)
			return fmt.Errorf("error inserting min/max: %v", err)
		}
	}

	return nil
}

func (s *service) GetUserMinMax(userID int) (float64, float64, error) {
	var min, max float64

	query := `SELECT min, max FROM settings WHERE userid = $1`
	row := s.db.QueryRow(query, userID)

	err := row.Scan(&min, &max)
	if err != nil {
		log.Printf("Error querying database for user %d: %v", userID, err) 
		if err == sql.ErrNoRows {
			return 0, 0, fmt.Errorf("settings not found for user")
		}
		return 0, 0, fmt.Errorf("error querying database: %v", err)
	}

	return min, max, nil
}

func (s *service) InsertAnalysis(sessionID int, timestamp, x, y, prob float64) error {
	query := `INSERT INTO analysis (session_id, timestamp, x, y, prob, created_at) VALUES ($1, $2, $3, $4, $5, NOW())`
	_, err := s.db.Exec(query, sessionID, timestamp, x, y, prob)
	if err != nil {
		log.Printf("Error inserting analysis data for session %d: %v", sessionID, err)
		return fmt.Errorf("error inserting analysis data: %v", err)
	}
	return nil
}

func (s *service) DeleteAnalysis(sessionID int) error {
	query := `DELETE FROM analysis WHERE session_id = $1`
	_, err := s.db.Exec(query, sessionID)
	if err != nil {
		log.Printf("Error deleting analysis data for session %d: %v", sessionID, err)
		return fmt.Errorf("failed to delete analysis data: %v", err)
	}
	return nil
}

func (s *service) DeleteSession(sessionID int) error {
	err := s.DeleteAnalysis(sessionID)
	if err != nil {
		return fmt.Errorf("error deleting analysis before session deletion: %v", err)
	}

	query := `DELETE FROM session WHERE id = $1`
	_, err = s.db.Exec(query, sessionID)
	if err != nil {
		log.Printf("Error deleting session %d: %v", sessionID, err)
		return fmt.Errorf("failed to delete session: %v", err)
	}
	return nil
}

func (s *service) UpdateSensitivity(userID int, sensitivity float64) error {
	query := `UPDATE settings SET sensitivity = $1 WHERE userid = $2`
	_, err := s.db.Exec(query, sensitivity, userID)
	if err != nil {
		return fmt.Errorf("error updating sensitivity: %v", err)
	}
	return nil
}

func (s *service) GetSensitivity(userID int) (float64, error) {
	var sensitivity float64

	query := `SELECT sensitivity FROM settings WHERE userid = $1`
	row := s.db.QueryRow(query, userID)

	err := row.Scan(&sensitivity)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("sensitivity not found")
		}
		return 0, fmt.Errorf("error querying database: %v", err)
	}

	return sensitivity, nil
}

func (s *service) AverageMinMax(userID int) error {
	var avgMin, avgMax float64

	query := `SELECT COALESCE(AVG(min), 0), COALESCE(AVG(max), 0) FROM session WHERE user_id = $1`
	row := s.db.QueryRow(query, userID)

	err := row.Scan(&avgMin, &avgMax)
	if err != nil {
		return fmt.Errorf("error calculating average min/max: %v", err)
	}

	updateQuery := `UPDATE settings SET min = $1, max = $2 WHERE userid = $3`
	_, err = s.db.Exec(updateQuery, avgMin, avgMax, userID)
	if err != nil {
		return fmt.Errorf("error updating settings: %v", err)
	}

	return nil
}
