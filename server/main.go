package main

import (
	"log"
	"net/http"

	"github.com/Harsimar2000/password-manager/database"
)

func main() {
	db, err := database.Open("vault.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	http.HandleFunc("/v1/auth/register", registerHandler(db))

	log.Println("🔒 password-manager API listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
