# Golang Custom Auth

A modular and beginner-friendly authentication system built in Go, designed to simplify authentication for developers. This project provides a foundation for user authentication with JWT-based login and registration, and plans to support OAuth 2.0 integrations (Google, Apple, GitHub, etc.) to streamline social logins and enhance security.

## Features
- **User Registration**: Securely register users with username and password (hashed with `bcrypt`).
- **User Login**: Authenticate users and issue JSON Web Tokens (JWT) for secure access.
- **Protected Endpoints**: Restrict access to routes using JWT middleware.
- **Planned Features**:
  - **OAuth 2.0 Support**: Integrate with Google, Apple, GitHub, and other providers for seamless social logins.
  - **Database Integration**: Support for PostgreSQL, MongoDB, or other databases to replace in-memory storage.
  - **Refresh Tokens**: Extend session management with secure token refresh.
  - **Password Recovery**: Email-based password reset functionality.
  - **Two-Factor Authentication (2FA)**: Add extra security layers.
  - **Role-Based Access Control (RBAC)**: Manage user permissions.

## Goals
The aim is to make authentication **easy for developers** by:
- Providing a plug-and-play auth module that’s simple to integrate.
- Supporting multiple auth providers (OAuth, social logins) with minimal configuration.
- Offering clear documentation and examples for quick setup.

## Prerequisites
- **Go**: Version 1.24.6 or higher (`go version go1.24.6 darwin/amd64` tested).
- **Git**: To clone and manage the repository.
- **curl** or **Postman**: For testing API endpoints.

## Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/Dearbornadeolu/golang-custom-auth.git
cd golang-custom-auth
2. Install DependenciesEnsure your go.mod is set up (already initialized as github.com/Dearbornadeolu/golang-custom-auth). Install dependencies:bash

go get github.com/gorilla/mux
go get github.com/dgrijalva/jwt-go
go get golang.org/x/crypto/bcrypt

3. Run the ApplicationStart the HTTP server:bash

go run main.go

The server runs on http://localhost:8080.UsageAPI EndpointsRegister: Create a new user.

POST /register
Content-Type: application/json

Example:bash

curl -X POST -H "Content-Type: application/json" -d '{"username":"testuser","password":"testpass"}' http://localhost:8080/register

Response: User testuser registered successfully
Login: Authenticate and receive a JWT.

POST /login
Content-Type: application/json

Example:bash

curl -X POST -H "Content-Type: application/json" -d '{"username":"testuser","password":"testpass"}' http://localhost:8080/login

Response: {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
Protected Endpoint: Access a restricted route with a valid JWT.

GET /protected
Authorization: Bearer <token>

Example:bash

curl -H "Authorization: Bearer <your-token>" http://localhost:8080/protected

Response: Welcome testuser! This is a protected endpoint.

Planned OAuth IntegrationTo make authentication easier, we’ll add support for OAuth 2.0 providers like Google and Apple. Here’s how developers will integrate them (planned):Google OAuthSetup: Register your app in the Google Cloud Console to get a Client ID and Client Secret.
Configuration: Store credentials in a .env file:

GOOGLE_CLIENT_ID=<your-client-id>
GOOGLE_CLIENT_SECRET=<your-client-secret>

Endpoints (planned):GET /auth/google/login: Redirect to Google’s login page.
GET /auth/google/callback: Handle the callback and issue a JWT.

