package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// setupTestDB creates a fresh temporary database and seeds it with one expired
// key and one valid key.
func setupTestDB(t *testing.T) {
	t.Helper()

	if db != nil {
		_ = db.Close()
		db = nil
	}

	dbPath = filepath.Join(t.TempDir(), "test_keys.db")

	InitDB()

	if err := SeedKeysIfEmpty(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
			db = nil
		}
	})
}

// setupEmptyTestDB creates a fresh temporary database without inserting keys.
func setupEmptyTestDB(t *testing.T) {
	t.Helper()

	if db != nil {
		_ = db.Close()
		db = nil
	}

	dbPath = filepath.Join(t.TempDir(), "test_keys.db")

	InitDB()

	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
			db = nil
		}
	})
}

func TestJWKSHandler(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	JWKSHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp map[string][]map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	keys, ok := resp["keys"]
	if !ok {
		t.Fatal("expected 'keys' field in response")
	}

	if len(keys) == 0 {
		t.Fatal("expected at least one valid key in JWKS")
	}

	firstKey := keys[0]
	if firstKey["kty"] != "RSA" {
		t.Errorf("expected kty RSA, got %v", firstKey["kty"])
	}
	if firstKey["alg"] != "RS256" {
		t.Errorf("expected alg RS256, got %v", firstKey["alg"])
	}
	if firstKey["use"] != "sig" {
		t.Errorf("expected use sig, got %v", firstKey["use"])
	}
	if firstKey["kid"] == "" {
		t.Error("expected non-empty kid")
	}
	if firstKey["n"] == "" {
		t.Error("expected non-empty n")
	}
	if firstKey["e"] == "" {
		t.Error("expected non-empty e")
	}
}

func TestJWKSHandlerNoKeys(t *testing.T) {
	setupEmptyTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	JWKSHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp map[string][]map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	keys, ok := resp["keys"]
	if !ok {
		t.Fatal("expected 'keys' field in response")
	}

	if len(keys) != 0 {
		t.Fatalf("expected empty keys array, got %d keys", len(keys))
	}
}

func TestAuthHandlerUnexpired(t *testing.T) {
	setupTestDB(t)

	expectedKey, err := GetValidKey()
	if err != nil {
		t.Fatalf("failed to get valid key: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w := httptest.NewRecorder()

	AuthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	tokenString := resp["token"]
	if tokenString == "" {
		t.Fatal("expected a token, got empty string")
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	if token.Header["kid"] == nil {
		t.Fatal("expected kid header in token")
	}

	if token.Header["kid"] != strconv.Itoa(expectedKey.Kid) {
		t.Errorf("expected kid %d, got %v", expectedKey.Kid, token.Header["kid"])
	}
}

func TestAuthHandlerExpired(t *testing.T) {
	setupTestDB(t)

	expectedKey, err := GetExpiredKey()
	if err != nil {
		t.Fatalf("failed to get expired key: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	w := httptest.NewRecorder()

	AuthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	tokenString := resp["token"]
	if tokenString == "" {
		t.Fatal("expected a token, got empty string")
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	if token.Header["kid"] == nil {
		t.Fatal("expected kid header in token")
	}

	if token.Header["kid"] != strconv.Itoa(expectedKey.Kid) {
		t.Errorf("expected kid %d, got %v", expectedKey.Kid, token.Header["kid"])
	}
}

func TestAuthHandlerRejectsGet(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w := httptest.NewRecorder()

	AuthHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", w.Code)
	}
}

func TestAuthHandlerExpiredQueryPresenceOnly(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/auth?expired", nil)
	w := httptest.NewRecorder()

	AuthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if resp["token"] == "" {
		t.Fatal("expected token in response")
	}
}
func TestJWKSHandlerPostAlsoReturnsOK(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	JWKSHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
}

func TestAuthHandlerTrailingSlash(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/", nil)
	w := httptest.NewRecorder()

	AuthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
}

func TestAuthHandlerExpiredTrailingSlash(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/?expired=true", nil)
	w := httptest.NewRecorder()

	AuthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
}