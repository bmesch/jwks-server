package main

import (
    "crypto/rand"
    "crypto/rsa"
    "log"
    "time"

    "github.com/google/uuid"
)

// Key represents an RSA key pair with a unique ID and expiry
type Key struct {
    PrivateKey *rsa.PrivateKey
    PublicKey  *rsa.PublicKey
    Kid        string
    Expiry     time.Time
}

// Key store (in-memory)
var keyStore = map[string]*Key{}

// GenerateKey creates a new RSA key pair with kid and expiry
func GenerateKey() *Key {
    // Generate 2048-bit RSA private key
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatal(err)
    }
    publicKey := &privateKey.PublicKey

    // Assign a unique kid using UUID
    kid := uuid.NewString()

    // Set expiry to 1 hour from now
    expiry := time.Now().Add(time.Hour)
key := &Key{
        PrivateKey: privateKey,
        PublicKey:  publicKey,
        Kid:        kid,
        Expiry:     expiry,
    }

    // Store in memory
    keyStore[kid] = key

    return key
}
// GetUnexpiredKeys returns all keys that haven't expired
func GetUnexpiredKeys() []*Key {
    var keys []*Key
    for _, k := range keyStore {
        if k.Expiry.After(time.Now()) {
            keys = append(keys, k)
        }
    }
    return keys
}

// GetExpiredKeys returns all keys that have expired
func GetExpiredKeys() []*Key {
    var keys []*Key
    for _, k := range keyStore {
        if k.Expiry.Before(time.Now()) {
            keys = append(keys, k)
        }
    }
    return keys
}

// GetKeyByKid retrieves a key by its kid
func GetKeyByKid(kid string) *Key {
    return keyStore[kid]
}
