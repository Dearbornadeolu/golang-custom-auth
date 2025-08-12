package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// RateLimiter struct to manage request limits
type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.Mutex
	limit    int           // Max requests allowed
	window   time.Duration // Time window for rate limiting
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if a request is allowed for the given IP
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	// Clean up old requests
	requests, exists := rl.requests[ip]
	if exists {
		// Remove requests older than the window
		validRequests := []time.Time{}
		for _, t := range requests {
			if now.Sub(t) < rl.window {
				validRequests = append(validRequests, t)
			}
		}
		rl.requests[ip] = validRequests
	}

	// Check if request is within limit
	if len(rl.requests[ip]) >= rl.limit {
		return false
	}

	// Add new request timestamp
	rl.requests[ip] = append(rl.requests[ip], now)
	return true
}

// User represents a user in the system
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// In-memory user store
var users = make(map[string]string) // username -> hashed password

// JWT secret key
var jwtKey = []byte("hjffddriofytrserzfgfhjfg")

// Refresh token secret key
var refreshJwtKey = []byte("cgdsersrthjkhoiyiturytsfghgh")

// Claims for access tokens
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Claims for refresh tokens
type RefreshClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Custom CORS middleware for control
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*") // Allow all origins for development
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimiterMiddleware adds rate limiting to handlers
func RateLimiterMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := r.RemoteAddr
			// For production,
			// if behind a proxy: r.Header.Get("X-Forwarded-For")

			if !rl.Allow(clientIP) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RegisterHandler handles user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Basic validation
	if user.Username == "" || user.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	if _, exists := users[user.Username]; exists {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Store user
	users[user.Username] = string(hashedPassword)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("User %s registered successfully", user.Username),
	})
}

// LoginHandler handles user login and issues both access and refresh tokens
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Check if user exists and password is correct
	hashedPassword, exists := users[user.Username]
	if !exists {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create access token (short-lived)
	accessTokenExpiration := time.Now().Add(15 * time.Minute) // 15 minutes
	accessClaims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: accessTokenExpiration.Unix(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Create refresh token (long-lived)
	refreshTokenExpiration := time.Now().Add(7 * 24 * time.Hour) // 7 days
	refreshClaims := &RefreshClaims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: refreshTokenExpiration.Unix(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(refreshJwtKey)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Return both tokens
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessTokenString,
		"refresh_token": refreshTokenString,
		"token_type":    "Bearer",
		"expires_in":    900, // 15 minutes in seconds
	})
}

// RefreshTokenHandler handles refresh token requests
func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if requestData.RefreshToken == "" {
		http.Error(w, "Missing refresh token", http.StatusUnauthorized)
		return
	}

	refreshClaims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(requestData.RefreshToken, refreshClaims, func(token *jwt.Token) (interface{}, error) {
		return refreshJwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Create a new access token
	accessTokenExpiration := time.Now().Add(15 * time.Minute)
	accessClaims := &Claims{
		Username: refreshClaims.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: accessTokenExpiration.Unix(),
		},
	}

	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	newAccessTokenString, err := newAccessToken.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Failed to generate new access token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": newAccessTokenString,
		"token_type":   "Bearer",
		"expires_in":   900, // 15 minutes in seconds
	})
}

// ProtectedHandler is a sample protected endpoint
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	// Remove "Bearer " prefix
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   fmt.Sprintf("Welcome %s! This is a protected endpoint.", claims.Username),
		"username":  claims.Username,
		"timestamp": time.Now().Unix(),
	})
}

func main() {
	// Initialize rate limiter: 100 requests per IP per minute
	rateLimiter := NewRateLimiter(100, time.Minute)

	router := mux.NewRouter()

	// Apply middlewares in order
	router.Use(CORSMiddleware)
	router.Use(RateLimiterMiddleware(rateLimiter))

	// Define endpoints
	router.HandleFunc("/register", RegisterHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/login", LoginHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/protected", ProtectedHandler).Methods("GET", "OPTIONS")
	router.HandleFunc("/refresh-token", RefreshTokenHandler).Methods("POST", "OPTIONS")

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}).Methods("GET")

	// Start server
	log.Println("Server starting on port 8080...")
	log.Printf("CORS enabled for all origins (development mode)")

	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
