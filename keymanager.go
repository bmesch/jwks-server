package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)


// Key represents a key loaded from the DB
type Key struct {
    Kid         int
    PrivateKey *rsa.PrivateKey
    PublicKey  *rsa.PublicKey
    Expiry     time.Time
}

// GenerateRSAKey creates a new 2048-bit RSA private key
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// PrivateKeyToPEM converts an RSA private key into PEM bytes for DB storage
func PrivateKeyToPEM(priv *rsa.PrivateKey) ([]byte, error) {
	der := x509.MarshalPKCS1PrivateKey(priv)

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(block), nil
}

// PEMToPrivateKey converts PEM bytes back into an RSA private key
func PEMToPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
