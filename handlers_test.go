package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --------------------------
// Helper: reset key store before each test
// --------------------------
func resetKeyStore() {
	keyStore = map[string]*Key{}
}

// --------------------------
// Test JWKS endpoint with keys
// --------------------------
func TestJWKSHandler(t *testing.T) {
	resetKeyStore()
	GenerateKey() // ensure at least one key exists

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	JWKSHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}

	if !strings.Contains(w.Body.String(), "keys") {
		t.Errorf("Expected 'keys' in response")
	}
}

// --------------------------
// Test JWKS endpoint with no keys
// --------------------------
func TestJWKSHandlerNoKeys(t *testing.T) {
	resetKeyStore() // no keys

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	JWKSHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}

	if !strings.Contains(w.Body.String(), `"keys":[]`) {
		t.Errorf("Expected empty keys array, got %s", w.Body.String())
	}
}

// --------------------------
// Test /auth with unexpired key
// --------------------------
func TestAuthHandlerUnexpired(t *testing.T) {
	resetKeyStore()
	key := GenerateKey() // unexpired key

	req := httptest.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()

	AuthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)

	tokenString := resp["token"]
	if tokenString == "" {
		t.Fatalf("Expected a token, got empty string")
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	if token.Header["kid"] != key.Kid {
		t.Errorf("Expected kid %v, got %v", key.Kid, token.Header["kid"])
	}

	claims := token.Claims.(jwt.MapClaims)
	expClaim := int64(claims["exp"].(float64))
	if expClaim != key.Expiry.Unix() {
		t.Errorf("Expected exp %v, got %v", key.Expiry.Unix(), expClaim)
	}
}

// --------------------------
// Test /auth with expired key
// --------------------------
func TestAuthHandlerExpired(t *testing.T) {
	resetKeyStore()
	expiredKey := &Key{
		PrivateKey: GenerateKey().PrivateKey,
		PublicKey:  GenerateKey().PublicKey,
		Kid:        "expired-test-key",
		Expiry:     time.Now().Add(-time.Hour).Truncate(time.Second),
	}
	keyStore[expiredKey.Kid] = expiredKey

	req := httptest.NewRequest("POST", "/auth?expired=true", nil)
	w := httptest.NewRecorder()

	AuthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)

	tokenString := resp["token"]
	if tokenString == "" {
		t.Fatalf("Expected a token, got empty string")
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	if token.Header["kid"] != "expired-test-key" {
		t.Errorf("Expected kid 'expired-test-key', got %v", token.Header["kid"])
	}

	claims := token.Claims.(jwt.MapClaims)
	expClaim := int64(claims["exp"].(float64))
	if expClaim != expiredKey.Expiry.Unix() {
		t.Errorf("Expected exp %v, got %v", expiredKey.Expiry.Unix(), expClaim)
	}
}

// --------------------------
// Test /auth with no unexpired keys
// --------------------------
func TestAuthHandlerNoUnexpiredKeys(t *testing.T) {
	resetKeyStore() // no keys

	req := httptest.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()

	AuthHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 Internal Server Error, got %d", w.Code)
	}
}

// --------------------------
// Test /auth?expired=true with no expired keys
// --------------------------
func TestAuthHandlerNoExpiredKeys(t *testing.T) {
	resetKeyStore()
	GenerateKey() // only unexpired key

	req := httptest.NewRequest("POST", "/auth?expired=true", nil)
	w := httptest.NewRecorder()

	AuthHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 Internal Server Error, got %d", w.Code)
	}
}
