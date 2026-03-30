package main

import (
	"testing"
	"time"
)

// TestSeedKeysIfEmpty verifies that a fresh database is seeded with exactly
// one expired key and one valid key.
func TestSeedKeysIfEmpty(t *testing.T) {
	setupTestDB(t)

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}

	if count != 2 {
		t.Fatalf("expected 2 keys in database, got %d", count)
	}
}

// TestGetValidKey verifies that GetValidKey returns an unexpired key.
func TestGetValidKey(t *testing.T) {
	setupTestDB(t)

	key, err := GetValidKey()
	if err != nil {
		t.Fatalf("expected valid key, got error: %v", err)
	}

	if key == nil {
		t.Fatal("expected valid key, got nil")
	}

	if !key.Expiry.After(time.Now()) {
		t.Errorf("expected valid key expiry in the future, got %v", key.Expiry)
	}
}

// TestGetExpiredKey verifies that GetExpiredKey returns an expired key.
func TestGetExpiredKey(t *testing.T) {
	setupTestDB(t)

	key, err := GetExpiredKey()
	if err != nil {
		t.Fatalf("expected expired key, got error: %v", err)
	}

	if key == nil {
		t.Fatal("expected expired key, got nil")
	}

	if key.Expiry.After(time.Now()) {
		t.Errorf("expected expired key expiry in the past, got %v", key.Expiry)
	}
}

// TestPEMRoundTrip verifies that a generated RSA key can be converted to PEM
// and then reconstructed without changing the modulus.
func TestPEMRoundTrip(t *testing.T) {
	priv, err := GenerateRSAKey()
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err := PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := PEMToPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.N.Cmp(priv.N) != 0 {
		t.Fatal("expected loaded private key to match original")
	}
}

// TestGetAllValidKeys verifies that only one valid key is returned from a
// freshly seeded database.
func TestGetAllValidKeys(t *testing.T) {
	setupTestDB(t)

	keys, err := GetAllValidKeys()
	if err != nil {
		t.Fatalf("expected valid keys, got error: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(keys))
	}

	if !keys[0].Expiry.After(time.Now()) {
		t.Errorf("expected valid key expiry in the future, got %v", keys[0].Expiry)
	}
}

// TestGetAllValidKeysEmpty verifies that no valid keys are returned from an
// empty database.
func TestGetAllValidKeysEmpty(t *testing.T) {
	setupEmptyTestDB(t)

	keys, err := GetAllValidKeys()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(keys) != 0 {
		t.Fatalf("expected 0 valid keys, got %d", len(keys))
	}
}

// TestGetValidKeyNoRows verifies that GetValidKey returns an error when no
// unexpired keys exist.
func TestGetValidKeyNoRows(t *testing.T) {
	setupEmptyTestDB(t)

	_, err := GetValidKey()
	if err == nil {
		t.Fatal("expected error when no valid keys exist")
	}
}

// TestGetExpiredKeyNoRows verifies that GetExpiredKey returns an error when no
// expired keys exist.
func TestGetExpiredKeyNoRows(t *testing.T) {
	setupEmptyTestDB(t)

	_, err := GetExpiredKey()
	if err == nil {
		t.Fatal("expected error when no expired keys exist")
	}
}

// TestInsertKey verifies that InsertKey successfully adds a new row to the
// database.
func TestInsertKey(t *testing.T) {
	setupTestDB(t)

	priv, err := GenerateRSAKey()
	if err != nil {
		t.Fatal(err)
	}

	exp := time.Now().Add(2 * time.Hour).Unix()

	if err := InsertKey(priv, exp); err != nil {
		t.Fatalf("InsertKey failed: %v", err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}

	if count != 3 {
		t.Fatalf("expected 3 keys after insert, got %d", count)
	}
}

// TestSeedKeysIfEmptyDoesNotDuplicate verifies that calling SeedKeysIfEmpty
// again does not create duplicate rows in an already seeded database.
func TestSeedKeysIfEmptyDoesNotDuplicate(t *testing.T) {
	setupTestDB(t)

	if err := SeedKeysIfEmpty(); err != nil {
		t.Fatal(err)
	}

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}

	if count != 2 {
		t.Fatalf("expected 2 keys after reseeding, got %d", count)
	}
}

// TestPEMToPrivateKeyInvalidData verifies that invalid PEM data returns an
// error during decoding.
func TestPEMToPrivateKeyInvalidData(t *testing.T) {
	_, err := PEMToPrivateKey([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM data")
	}
}
