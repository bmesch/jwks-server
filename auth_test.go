package main

import (
	"testing"
	"time"
)

// Test key generation
func TestGenerateKey(t *testing.T) {
	resetKeyStore()

	key := GenerateKey()
	if key == nil {
		t.Fatal("Expected a key, got nil")
	}

	if key.Kid == "" {
		t.Error("Expected kid to be set")
	}

	if key.PrivateKey == nil || key.PublicKey == nil {
		t.Error("Expected RSA keys to be generated")
	}

	// Check expiry is in the future
	if key.Expiry.Before(time.Now()) {
		t.Errorf("Expected expiry in the future, got %v", key.Expiry)
	}

	// Check that keyStore contains the key
	storedKey := keyStore[key.Kid]
	if storedKey == nil {
		t.Error("Key was not stored in keyStore")
	}
}

// Test GetUnexpiredKeys and GetExpiredKeys
func TestKeyRetrieval(t *testing.T) {
	resetKeyStore()

	// Add unexpired key
	unexpired := GenerateKey()

	// Add expired key
	expired := &Key{
		PrivateKey: unexpired.PrivateKey,
		PublicKey:  unexpired.PublicKey,
		Kid:        "expired-test",
		Expiry:     time.Now().Add(-time.Hour),
	}
	keyStore[expired.Kid] = expired

	unexpiredKeys := GetUnexpiredKeys()
	if len(unexpiredKeys) != 1 || unexpiredKeys[0].Kid != unexpired.Kid {
		t.Errorf("Expected 1 unexpired key with kid %v, got %v", unexpired.Kid, unexpiredKeys)
	}

	expiredKeys := GetExpiredKeys()
	if len(expiredKeys) != 1 || expiredKeys[0].Kid != expired.Kid {
		t.Errorf("Expected 1 expired key with kid %v, got %v", expired.Kid, expiredKeys)
	}
}

// Test GetKeyByKid
func TestGetKeyByKid(t *testing.T) {
	resetKeyStore()
	key := GenerateKey()

	result := GetKeyByKid(key.Kid)
	if result == nil {
		t.Errorf("Expected to retrieve key by kid %v", key.Kid)
	}

	result = GetKeyByKid("nonexistent")
	if result != nil {
		t.Error("Expected nil for nonexistent kid")
	}
}
