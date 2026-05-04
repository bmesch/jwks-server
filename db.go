package main

import (
	"crypto/rsa"
	"database/sql"
	"log"
	_ "modernc.org/sqlite"
	"time"
)

// db is the global database connection used throughout the application.
var db *sql.DB
var dbPath = "./totally_not_my_privateKeys.db"

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
	createTables := `
	CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		email TEXT UNIQUE,
		date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS auth_logs(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_ip TEXT NOT NULL,
		request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`

	_, err = db.Exec(createTables)
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

	encryptedKey, err := Encrypt(pemBytes)
	if err != nil {
		return err
	}

	_, err = db.Exec(
		"INSERT INTO keys(key, exp) VALUES(?, ?)",
		encryptedKey,
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
	var encryptedBytes []byte
	var exp int64

	err := row.Scan(&kid, &encryptedBytes, &exp)
	if err != nil {
		return nil, err
	}

	pemBytes, err := Decrypt(encryptedBytes)
	if err != nil {
		return nil, err
	}

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
	var encryptedBytes []byte
	var exp int64

	err := row.Scan(&kid, &encryptedBytes, &exp)
	if err != nil {
		return nil, err
	}

	pemBytes, err := Decrypt(encryptedBytes)
	if err != nil {
		return nil, err
	}

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
		var encryptedBytes []byte
		var exp int64

		err := rows.Scan(&kid, &encryptedBytes, &exp)
		if err != nil {
			return nil, err
		}

		pemBytes, err := Decrypt(encryptedBytes)
		if err != nil {
			return nil, err
		}

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

// CreateUser stores a new registered user
func CreateUser(username, email, passwordHash string) error {
	_, err := db.Exec(`
		INSERT INTO users(username, email, password_hash)
		VALUES(?, ?, ?)
	`, username, email, passwordHash)

	return err
}

// GetUserIDByUsername returns the database id for a username
func GetUserIDByUsername(username string) (int, error) {
	var userID int

	err := db.QueryRow(`
		SELECT id FROM users
		WHERE username = ?
	`, username).Scan(&userID)

	return userID, err
}

// LogAuthRequest stores a successful auth request
// LogAuthRequest stores a successful auth request.
func LogAuthRequest(requestIP string, userID *int) error {
	_, err := db.Exec(`
		INSERT INTO auth_logs(request_ip, user_id)
		VALUES(?, ?)
	`, requestIP, userID)

	return err
}
