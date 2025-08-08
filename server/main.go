package main

import (
	"log"
	"net/http"

	"github.com/Harsimar2000/password-manager/database"
)

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Allow your dev front‑end
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")

		// If you need cookies/Auth headers:
		// w.Header().Set("Access-Control-Allow-Credentials", "true")

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle pre‑flight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	db, err := database.Open("vault.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/register", registerHandler(db))
	mux.HandleFunc("/v1/salt/{email}", saltHandler(db))
	mux.HandleFunc("/v1/auth/login", loginHandler(db))

	log.Println("🔒 password-manager API listening on :8080")
	if err := http.ListenAndServe(":8080", withCORS(mux)); err != nil {
		log.Fatal(err)
	}
}
