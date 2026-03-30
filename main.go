package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	InitDB()

	if err := SeedKeysIfEmpty(); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)
	http.HandleFunc("/auth/", AuthHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := ":" + port
	log.Printf("Server running on http://127.0.0.1:%s", port)
	log.Fatal(http.ListenAndServe(addr, nil))
}