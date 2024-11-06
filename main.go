package main

import (
	"log"
	database "password-manager/db" // Add this line
)
func main() {
    // Establish a connection to the SQLite database
    db := database.ConnectDB()  // Changed from ConnectDB to Connect
    defer db.Close()

    // Create the necessary tables in the database
    database.CreateTables(db)    // Changed from CreateTables to createTable

    log.Println("Database connection established and tables created successfully!")
}