package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	//"errors"

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

	GetUserByToken(token string) (string, bool, error)

	GetUserSessions(userID int) ([]Session, error)

	GetSessionAnalysis(sessionID int) ([]Analysis, error)

	GetUserIDByEmail(email string) (int, error)

	CreateSession(name string, userID int, startTime, endTime string, v_min, v_max, a_min, a_max float64) (int, error)

	InsertAnalysis(entries []AnalysisData) error

	DeleteAnalysis(sessionID int) error

	DeleteSession(sessionID int) error

	UpdateSensitivity(userID int, newSensitivity float64) error

	GetSensitivity(userID int) (float64, error)

	GetUserMinMaxVar(userID int) (float64, float64, error)

	GetUserMinMaxAcc(userID int) (float64, float64, error)

	AverageMinMaxVar(userID int) error

	AverageMinMaxAcc(userID int) error

	UpdateMinMaxVar(userID int, min, max float64) error

	UpdateMinMaxAcc(userID int, min, max float64) error

	UpdateUserMinMaxVar(userID int) error

	UpdateUserMinMaxAcc(userID int) error

	InsertSettings(userID int, varMin, varMax, accMin, accMax float64) error

	GetUserSettings(userID int) (bool, bool, bool, float64, error)

	UpdateMinMaxSetting(userID int, minMax bool) error

	UpdateNormalization(userID int, normalization bool) error

	UpdateGraphing(userID int, plotting bool) error
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

// GetUserByToken gets the email of the user through token input
func (s *service) GetUserByToken(token string) (string, bool, error) {
	var email string

	query := `SELECT email FROM Users WHERE auth_token = $1`
	row := s.db.QueryRow(query, token)

	err := row.Scan(&email)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, fmt.Errorf("error querying database: %v", err)
	}

	return email, true, nil
}

type Session struct {
	Name      string
	ID        int
	UserID    int
	StartTime string
	EndTime   string
	VarMin    float64
	VarMax    float64
	AccMin    float64
	AccMax    float64
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

type AnalysisData struct {
	SessionID int     `json:"session_id"`
	Timestamp float64 `json:"timestamp"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Prob      float64 `json:"prob"`
}

func (s *service) GetUserSessions(userID int) ([]Session, error) {
	var sessions []Session

	query := `SELECT name, id, user_id, start_time, end_time, var_min, var_max, acc_min, acc_max, created_at FROM session WHERE user_id = $1 ORDER BY start_time DESC`
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ses Session
		err := rows.Scan(&ses.Name, &ses.ID, &ses.UserID, &ses.StartTime, &ses.EndTime, &ses.VarMin, &ses.VarMax, &ses.AccMin, &ses.AccMax, &ses.CreatedAt)
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

func (s *service) CreateSession(name string, userID int, startTime, endTime string, v_min, v_max, a_min, a_max float64) (int, error) {
	// Updated query to return the generated session ID
	query := `
		INSERT INTO session (name, user_id, start_time, end_time, var_min, var_max, acc_min, acc_max) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`

	var sessionID int
	err := s.db.QueryRow(query, name, userID, startTime, endTime, v_min, v_max, a_min, a_max).Scan(&sessionID)
	if err != nil {
		return 0, fmt.Errorf("error inserting session: %v", err)
	}

	// Return the session ID
	return sessionID, nil
}

func (s *service) InsertAnalysis(entries []AnalysisData) error {
	if len(entries) == 0 {
		return fmt.Errorf("no analysis data to insert")
	}

	query := `INSERT INTO analysis (session_id, timestamp, x, y, prob, created_at) VALUES `
	values := []interface{}{}
	placeholders := []string{}

	for i, entry := range entries {
		offset := i * 5
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, NOW())",
			offset+1, offset+2, offset+3, offset+4, offset+5))

		values = append(values, entry.SessionID, entry.Timestamp, entry.X, entry.Y, entry.Prob)
	}

	query += strings.Join(placeholders, ", ")

	_, err := s.db.Exec(query, values...)
	if err != nil {
		log.Printf("Error inserting batch analysis data: %v", err)
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

func (s *service) UpdateMinMaxSetting(userID int, minMax bool) error {
	query := `UPDATE settings SET min_max = $1 WHERE userid = $2`
	_, err := s.db.Exec(query, minMax, userID)
	if err != nil {
		return fmt.Errorf("error updating min_max setting: %v", err)
	}
	return nil
}

func (s *service) UpdateNormalization(userID int, normalization bool) error {
	query := `UPDATE settings SET affine = $1 WHERE userid = $2`
	_, err := s.db.Exec(query, normalization, userID)
	if err != nil {
		return fmt.Errorf("error updating normalization: %v", err)
	}
	return nil
}

func (s *service) UpdateGraphing(userID int, plotting bool) error {
	query := `UPDATE settings SET plotting = $1 WHERE userid = $2`
	_, err := s.db.Exec(query, plotting, userID)
	if err != nil {
		return fmt.Errorf("error updating plotting: %v", err)
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

func (s *service) GetUserMinMaxVar(userID int) (float64, float64, error) {
	var varMin, varMax float64

	query := `SELECT var_min, var_max FROM settings WHERE userid = $1`
	row := s.db.QueryRow(query, userID)

	err := row.Scan(&varMin, &varMax)
	if err != nil {
		log.Printf("Error querying variance min/max for user %d: %v", userID, err)
		if err == sql.ErrNoRows {
			return 0, 0, fmt.Errorf("settings not found for user")
		}
		return 0, 0, fmt.Errorf("error querying database: %v", err)
	}

	return varMin, varMax, nil
}

func (s *service) GetUserMinMaxAcc(userID int) (float64, float64, error) {
	var accMin, accMax float64

	query := `SELECT acc_min, acc_max FROM settings WHERE userid = $1`
	row := s.db.QueryRow(query, userID)

	err := row.Scan(&accMin, &accMax)
	if err != nil {
		log.Printf("Error querying acceleration min/max for user %d: %v", userID, err)
		if err == sql.ErrNoRows {
			return 0, 0, fmt.Errorf("settings not found for user")
		}
		return 0, 0, fmt.Errorf("error querying database: %v", err)
	}

	return accMin, accMax, nil
}

func (s *service) AverageMinMaxVar(userID int) error {
	var avgVarMin, avgVarMax float64

	query := `SELECT COALESCE(AVG(var_min), 0), COALESCE(AVG(var_max), 0) FROM session WHERE user_id = $1`
	row := s.db.QueryRow(query, userID)

	err := row.Scan(&avgVarMin, &avgVarMax)
	if err != nil {
		return fmt.Errorf("error calculating average variance min/max: %v", err)
	}

	updateQuery := `UPDATE settings SET var_min = $1, var_max = $2 WHERE userid = $3`
	_, err = s.db.Exec(updateQuery, avgVarMin, avgVarMax, userID)
	if err != nil {
		return fmt.Errorf("error updating variance min/max: %v", err)
	}

	return nil
}

func (s *service) AverageMinMaxAcc(userID int) error {
	var avgAccMin, avgAccMax float64

	query := `SELECT COALESCE(AVG(acc_min), 0), COALESCE(AVG(acc_max), 0) FROM session WHERE user_id = $1`
	row := s.db.QueryRow(query, userID)

	err := row.Scan(&avgAccMin, &avgAccMax)
	if err != nil {
		return fmt.Errorf("error calculating average acceleration min/max: %v", err)
	}

	updateQuery := `UPDATE settings SET acc_min = $1, acc_max = $2 WHERE userid = $3`
	_, err = s.db.Exec(updateQuery, avgAccMin, avgAccMax, userID)
	if err != nil {
		return fmt.Errorf("error updating acceleration min/max: %v", err)
	}

	return nil
}

func (s *service) UpdateMinMaxVar(userID int, varMin, varMax float64) error {
	query := `UPDATE settings SET var_min = $1, var_max = $2 WHERE userid = $3`
	result, err := s.db.Exec(query, varMin, varMax, userID)
	if err != nil {
		log.Printf("Database update error for variance min/max for user %d: %v", userID, err)
		return fmt.Errorf("error updating variance min/max: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error checking affected rows for variance min/max for user %d: %v", userID, err)
		return fmt.Errorf("error checking variance min/max update status: %v", err)
	}

	if rowsAffected == 0 {
		insertQuery := `INSERT INTO settings (userid, var_min, var_max, plotting, affine, min_max) VALUES ($1, $2, $3, false, false, false)`
		_, err := s.db.Exec(insertQuery, userID, varMin, varMax)
		if err != nil {
			log.Printf("Database insert error for variance min/max for user %d: %v", userID, err)
			return fmt.Errorf("error inserting variance min/max: %v", err)
		}
	}

	return nil
}

func (s *service) UpdateMinMaxAcc(userID int, accMin, accMax float64) error {
	query := `UPDATE settings SET acc_min = $1, acc_max = $2 WHERE userid = $3`
	result, err := s.db.Exec(query, accMin, accMax, userID)
	if err != nil {
		log.Printf("Database update error for acceleration min/max for user %d: %v", userID, err)
		return fmt.Errorf("error updating acceleration min/max: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error checking affected rows for acceleration min/max for user %d: %v", userID, err)
		return fmt.Errorf("error checking acceleration min/max update status: %v", err)
	}

	if rowsAffected == 0 {
		insertQuery := `INSERT INTO settings (userid, acc_min, acc_max, plotting, affine, min_max) VALUES ($1, $2, $3, false, false, false)`
		_, err := s.db.Exec(insertQuery, userID, accMin, accMax)
		if err != nil {
			log.Printf("Database insert error for acceleration min/max for user %d: %v", userID, err)
			return fmt.Errorf("error inserting acceleration min/max: %v", err)
		}
	}

	return nil
}

func (s *service) UpdateUserMinMaxVar(userID int) error {
	var useAverage bool

	query := `SELECT min_max FROM settings WHERE userid = $1`
	row := s.db.QueryRow(query, userID)

	err := row.Scan(&useAverage)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("yah momma")
			return fmt.Errorf("settings not found for user")
		}
		return fmt.Errorf("error querying settings: %v", err)
	}

	if useAverage {
		return s.AverageMinMaxVar(userID)
	} else {
		var varMin, varMax float64

		recentQuery := `
			SELECT var_min, var_max FROM session
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT 1`
		recentRow := s.db.QueryRow(recentQuery, userID)

		err := recentRow.Scan(&varMin, &varMax)
		if err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("no sessions found for user")
			}
			return fmt.Errorf("error retrieving recent variance session data: %v", err)
		}

		return s.UpdateMinMaxVar(userID, varMin, varMax)
	}
}

func (s *service) UpdateUserMinMaxAcc(userID int) error {
	var useAverage bool

	query := `SELECT min_max FROM settings WHERE userid = $1`
	row := s.db.QueryRow(query, userID)

	err := row.Scan(&useAverage)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("settings not found for user")
		}
		return fmt.Errorf("error querying settings: %v", err)
	}

	if useAverage {
		return s.AverageMinMaxAcc(userID)
	} else {
		var accMin, accMax float64

		recentQuery := `
			SELECT acc_min, acc_max FROM session
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT 1`
		recentRow := s.db.QueryRow(recentQuery, userID)

		err := recentRow.Scan(&accMin, &accMax)
		if err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("no sessions found for user")
			}
			return fmt.Errorf("error retrieving recent acceleration session data: %v", err)
		}

		return s.UpdateMinMaxAcc(userID, accMin, accMax)
	}
}

func (s *service) InsertSettings(userID int, varMin, varMax, accMin, accMax float64) error {
	var plotting, affine, minMax bool

	query := `SELECT plotting, affine, min_max FROM settings WHERE userid = $1`
	row := s.db.QueryRow(query, userID)

	err := row.Scan(&plotting, &affine, &minMax)
	if err != nil {
		if err == sql.ErrNoRows {
			insertQuery := `
				INSERT INTO settings (
					userid,
					var_min,
					var_max,
					acc_min,
					acc_max,
					plotting,
					affine,
					min_max
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			`

			plotting = true
			affine = false
			minMax = false

			_, err := s.db.Exec(insertQuery, userID, varMin, varMax, accMin, accMax, plotting, affine, minMax)
			if err != nil {
				return fmt.Errorf("error inserting default settings for user %d: %v", userID, err)
			}

			log.Printf("Default settings inserted for user %d", userID)
			return nil
		}
		return fmt.Errorf("error querying settings for user %d: %v", userID, err)
	}

	log.Printf("Settings already exist for user %d", userID)
	return nil
}

func (s *service) GetUserSettings(userID int) (bool, bool, bool, float64, error) {
	var plotting, affine, minMax bool
	var sensitivity float64

	// Query to retrieve the settings from the database
	query := `SELECT plotting, affine, min_max, sensitivity FROM settings WHERE userid = $1`
	row := s.db.QueryRow(query, userID)

	// Attempt to scan the settings
	err := row.Scan(&plotting, &affine, &minMax, &sensitivity)
	if err != nil {
		if err == sql.ErrNoRows {
			// If no settings are found, insert default settings
			fmt.Printf("No Rows Error for user %d, inserting default settings\n", userID)
			// Call InsertSettings to insert default values for the user
			var varMin, varMax, accMin, accMax float64
			varMin = 0.0   // Set appropriate default values for varMin
			varMax = 100.0 // Set appropriate default values for varMax
			accMin = 0.0   // Set appropriate default values for accMin
			accMax = 100.0 // Set appropriate default values for accMax

			err := s.InsertSettings(userID, varMin, varMax, accMin, accMax)
			if err != nil {
				// If there was an error inserting the settings, return the error
				return false, false, false, 1.0, fmt.Errorf("failed to insert default settings for user %d: %v", userID, err)
			}

			// After inserting, return the default settings
			return true, false, false, 1.0, nil
		}
		// If there's another error, return it
		return false, false, false, 1.0, fmt.Errorf("error querying settings for user %d: %v", userID, err)
	}

	// Return the found settings
	return plotting, affine, minMax, sensitivity, nil
}
