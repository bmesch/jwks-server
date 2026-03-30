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

	var key *Key
	var err error
	
	if r.Method != http.MethodPost {
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	return
	}	

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
		"sub": "userABC",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})

	token.Header["kid"] = strconv.Itoa(key.Kid)

	tokenString, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}