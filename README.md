Brooke Mesch

11834510

CSCE 3550.001

Project 1: JWKS Server 



JWKS Server - Go Implementation



Run server:

go run main.go keymanager.go handlers.go



Endpoints:

GET /.well-known/jwks.json

POST /auth

POST /auth?expired=true



Run tests:

go test ./... -cover

