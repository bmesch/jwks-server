package main

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

var authRequests = make(map[string][]time.Time)

func JWKFromKey(k *Key) JWK {
	rsaKey := k.PublicKey
	nBytes := rsaKey.N.Bytes()
	eBytes := big.NewInt(int64(rsaKey.E)).Bytes()

	return JWK{
		Kty: "RSA",
		Kid: strconv.Itoa(k.Kid),
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	keys, err := GetAllValidKeys()
	if err != nil {
		http.Error(w, "Failed to load keys", http.StatusInternalServerError)
		return
	}

	jwks := []JWK{}
	for _, key := range keys {
		jwks = append(jwks, JWKFromKey(key))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": jwks,
	})
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	_, expiredPresent := r.URL.Query()["expired"]

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestIP := r.RemoteAddr
	now := time.Now()

	requests := authRequests[requestIP]
	var recent []time.Time

	for _, t := range requests {
		if now.Sub(t) < time.Second {
			recent = append(recent, t)
		}
	}

	if len(recent) >= 10 {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	authRequests[requestIP] = append(recent, now)

	var authReq struct {
		Username string `json:"username"`
	}

	_ = json.NewDecoder(r.Body).Decode(&authReq)

	var key *Key
	var err error

	if expiredPresent {
		key, err = GetExpiredKey()
	} else {
		key, err = GetValidKey()
	}

	if err != nil {
		http.Error(w, "No suitable key available", http.StatusInternalServerError)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": authReq.Username,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})

	token.Header["kid"] = strconv.Itoa(key.Kid)

	tokenString, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	var userID *int
	if authReq.Username != "" {
		id, err := GetUserIDByUsername(authReq.Username)
		if err == nil {
			userID = &id
		}
	}

	if err := LogAuthRequest(requestIP, userID); err != nil {
		http.Error(w, "Failed to log auth request", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}
