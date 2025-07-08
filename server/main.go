package main

import (
	"fmt"
	"log"

	"github.com/Harsimar2000/password-manager/database"
)

func main() {
	db, err := database.Open("vault.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var tables []string
	_ = db.Select(&tables, "SELECT name FROM sqlite_master WHERE type='table'")
	fmt.Println("SQLite ready, tables:", tables)
}
