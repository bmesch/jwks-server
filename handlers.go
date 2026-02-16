package main

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --------------------------
// JWK struct for JWKS output
// --------------------------
type JWK struct {
	Kty string `json:"kty"` // Key Type
	Kid string `json:"kid"` // Key ID
	Use string `json:"use"` // "sig"
	Alg string `json:"alg"` // Algorithm
	N   string `json:"n"`   // Modulus
	E   string `json:"e"`   // Exponent
}

// --------------------------
// Convert *Key to JWK
// --------------------------
func JWKFromKey(k *Key) JWK {
	rsaKey := k.PublicKey
	nBytes := rsaKey.N.Bytes()
	eBytes := big.NewInt(int64(rsaKey.E)).Bytes()

	return JWK{
		Kty: "RSA",
		Kid: k.Kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

// --------------------------
// JWKSHandler serves unexpired keys
// --------------------------
func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	// always initialize slice to avoid null in JSON
	jwks := []JWK{}

	for _, key := range GetUnexpiredKeys() {
		jwks = append(jwks, JWKFromKey(key))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": jwks,
	})
}

// --------------------------
// AuthHandler issues JWTs
// --------------------------
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	expiredParam := r.URL.Query().Get("expired") == "true"

	var key *Key
	if expiredParam {
		expiredKeys := GetExpiredKeys()
		if len(expiredKeys) == 0 {
			http.Error(w, "No expired keys available", http.StatusInternalServerError)
			return
		}
		key = expiredKeys[0] // pick first expired key
	} else {
		unexpiredKeys := GetUnexpiredKeys()
		if len(unexpiredKeys) == 0 {
			http.Error(w, "No unexpired keys available", http.StatusInternalServerError)
			return
		}
		key = unexpiredKeys[0] // pick first unexpired key
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user123",
		"iat": time.Now().Unix(),
		"exp": key.Expiry.Unix(),
	})

	// Set kid in header
	token.Header["kid"] = key.Kid

	// Sign JWT
	tokenString, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	// Return as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

// --------------------------
// Optional: helper to convert RSA key to JWK for single key
// (already done via JWKFromKey)
// --------------------------
