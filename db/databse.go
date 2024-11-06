package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// ConnectDB establishes a connection to the SQLite database
func ConnectDB() *sql.DB {
	// Open a connection to the database
	db, err := sql.Open("sqlite3", "./db/password_manager.db")
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	// Check if the connection is successful
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping the database: %v", err)
	}

	log.Println("Database connection established successfully")
	return db
}

// CreateTables creates the necessary tables in the SQLite database
func CreateTables(db *sql.DB) {
	// SQL statement to create the passwords table
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS passwords (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		website TEXT NOT NULL,
		username TEXT NOT NULL,
		encrypted_password TEXT NOT NULL,
		notes TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`

	// Execute the SQL statement
	_, err := db.Exec(createTableQuery)
	if err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}

	log.Println("Tables created successfully")
}
