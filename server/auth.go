package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/argon2"
	"net/http"
	"net/mail"
	"strings"
)

type registerationRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerationResponse struct {
	UserID string `json:"user_id"`
}

type saltResponse struct {
	Salt []byte `json:"salt"`
}

/* Argon2 parameter  */

var (
	authTime, authMem uint32 = 2, 32 * 1024 // login hash
	keyTime, keyMem   uint32 = 3, 64 * 1024 // master key
)

/* ---------- handler factory ---------- */

func registerHandler(db *sqlx.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow only POST
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		//  Decode JSON
		var req registerationRequest

		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			fmt.Println("asf")
		}
		req.Email = strings.TrimSpace(req.Email)
		_, err := mail.ParseAddress(req.Email)

		if err != nil {
			http.Error(w, "Invalid email address", http.StatusBadRequest)
			return
		}

		if len(req.Password) < 8 {
			http.Error(w, "Password too short", http.StatusBadRequest)
			return
		}
		//  salt, hashes, keys

		salt := make([]byte, 16)
		rand.Read(salt)

		password_hash := argon2.IDKey([]byte(req.Password), salt, authTime, authMem, 1, 32)
		mk := argon2.IDKey([]byte(req.Password), salt, keyTime, keyMem, 1, 32)

		vk := make([]byte, 32)
		rand.Read(vk)

		block, _ := aes.NewCipher(mk)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)
		vk_enc := append(nonce, gcm.Seal(nil, nonce, vk, nil)...)

		/* 4. Insert user row */
		userID := uuid.NewString()
		hi, err := db.NamedExec(` INSERT INTO users (id,email,salt,pwd_hash,vk_enc)
								VALUES (:id,:email,:salt,:pwd_hash,:vk_enc)`,

			map[string]any{"id": userID, "email": req.Email, "salt": salt, "pwd_hash": password_hash, "vk_enc": vk_enc})

		if err != nil {
			http.Error(w, "e-mail already in use", http.StatusBadRequest)
			return
		}
		fmt.Println(hi)

		//  Send JSON response
		var res registerationResponse
		res.UserID = userID
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(res.UserID)
	}
}

func saltHandler(db *sqlx.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

		email, found := strings.CutPrefix(r.URL.Path, "/v1/salt/")

		if found == false {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}

		var count int
		err := db.QueryRow("SELECT count(*) FROM users WHERE email = ?", email).Scan(&count)

		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}

		if count == 1 {
			err := db.QueryRow("select salt from users where email=?", email).Scan(&salt)
			fmt.Println(salt)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		} else {
			http.Error(w, "Wrong email address", http.StatusBadRequest)
		}

		salt := make([]byte, 16)
		var res saltResponse
		res.Salt = salt

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(res.Salt)
	}
}
