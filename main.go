package main

import (
	"fmt"
    "log"
    "net/http"
)

func main() {
    // Generate at least on key at startup
	key := GenerateKey()
    fmt.Println("Generated key with kid:", key.Kid)
    fmt.Println("Expiry:", key.Expiry)

	// Register JWKS endpoint
	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)

	// Register Auth endpoint
	http.HandleFunc("/auth", AuthHandler)


    log.Println("Server running on http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

