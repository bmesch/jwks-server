## Brooke Mesch
## 11834510
## CSCE 3550
## Project 2 - Extending the JWKS Server

## Run
go run .

## Test
go test ./... -cover

## Endpoints
POST /auth
POST /auth?expired=true
GET /.well-known/jwks.json