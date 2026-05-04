package main

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

// request format
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

// response format
type RegisterResponse struct {
	Password string `json:"password"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Username == "" {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate password (UUIDv4)
	password := uuid.New().String()

	// Hash password using Argon2
	hash := argon2.IDKey(
		[]byte(password),
		[]byte("somesalt"), // we’ll improve this later if needed
		1,                  // time
		64*1024,            // memory
		4,                  // threads
		32,                 // key length
	)

	passwordHash := string(hash)

	// Store user
	err = CreateUser(req.Username, req.Email, passwordHash)
	if err != nil {
		http.Error(w, "User creation failed", http.StatusInternalServerError)
		return
	}

	resp := RegisterResponse{
		Password: password,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}