package main

import (
	"crypto/rsa"
	"database/sql"
	_ "modernc.org/sqlite"
	"log"
	"time"
)

// db is the global database connection used throughout the application.
var db *sql.DB
var dbPath = "totally_not_my_privateKeys.db"

// InitDB opens (or creates) the SQLite database file and ensures the required
// keys table exists. This function must be called before any database operations.
func InitDB() {
	var err error

	// Open or create the SQLite database file
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}

	// Create the keys table if it does not already exist
	createTable := `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Database initialized")
}

// InsertKey stores a PEM-encoded RSA private key along with its expiration time.
// The expiration time is stored as a Unix timestamp.
func InsertKey(priv *rsa.PrivateKey, exp int64) error {
	pemBytes, err := PrivateKeyToPEM(priv)
	if err != nil {
		return err
	}

	// Use parameterized query to safely insert key and expiration
	_, err = db.Exec(
		"INSERT INTO keys(key, exp) VALUES(?, ?)",
		pemBytes,
		exp,
	)
	return err
}

// SeedKeysIfEmpty inserts one expired key and one valid key into the database
// if the table is currently empty. This ensures the application always has
// keys available for testing and JWT signing.
func SeedKeysIfEmpty() error {
	var count int

	// Check how many keys currently exist in the database
	err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		return err
	}

	// If keys already exist, do nothing
	if count > 0 {
		return nil
	}

	// Generate one expired key and one valid key
	expiredKey, err := GenerateRSAKey()
	if err != nil {
		return err
	}

	validKey, err := GenerateRSAKey()
	if err != nil {
		return err
	}

	now := time.Now().Unix()

	// Insert expired key (past timestamp)
	if err := InsertKey(expiredKey, now-3600); err != nil {
		return err
	}

	// Insert valid key (future timestamp)
	if err := InsertKey(validKey, now+3600); err != nil {
		return err
	}

	log.Println("Seeded database with expired and valid keys")
	return nil
}

// GetValidKey retrieves a single unexpired key from the database.
// It returns the key with the earliest expiration time that is still valid.
func GetValidKey() (*Key, error) {
	now := time.Now().Unix()

	row := db.QueryRow(`
		SELECT kid, key, exp
		FROM keys
		WHERE exp > ?
		ORDER BY exp ASC
		LIMIT 1
	`, now)

	var kid int
	var pemBytes []byte
	var exp int64

	err := row.Scan(&kid, &pemBytes, &exp)
	if err != nil {
		return nil, err
	}

	// Convert stored PEM back into RSA private key
	priv, err := PEMToPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	return &Key{
		Kid:        kid,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Expiry:     time.Unix(exp, 0),
	}, nil
}

// GetExpiredKey retrieves a single expired key from the database.
// It returns the most recently expired key.
func GetExpiredKey() (*Key, error) {
	now := time.Now().Unix()

	row := db.QueryRow(`
		SELECT kid, key, exp
		FROM keys
		WHERE exp <= ?
		ORDER BY exp DESC
		LIMIT 1
	`, now)

	var kid int
	var pemBytes []byte
	var exp int64

	err := row.Scan(&kid, &pemBytes, &exp)
	if err != nil {
		return nil, err
	}

	// Convert stored PEM back into RSA private key
	priv, err := PEMToPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	return &Key{
		Kid:        kid,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Expiry:     time.Unix(exp, 0),
	}, nil
}

// GetAllValidKeys retrieves all unexpired keys from the database.
// These keys are used to construct the JWKS response.
func GetAllValidKeys() ([]*Key, error) {
	now := time.Now().Unix()

	rows, err := db.Query(`
		SELECT kid, key, exp
		FROM keys
		WHERE exp > ?
		ORDER BY kid ASC
	`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*Key

	for rows.Next() {
		var kid int
		var pemBytes []byte
		var exp int64

		err := rows.Scan(&kid, &pemBytes, &exp)
		if err != nil {
			return nil, err
		}

		// Convert stored PEM back into RSA private key
		priv, err := PEMToPrivateKey(pemBytes)
		if err != nil {
			return nil, err
		}

		keys = append(keys, &Key{
			Kid:        kid,
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
			Expiry:     time.Unix(exp, 0),
		})
	}

	return keys, rows.Err()
}