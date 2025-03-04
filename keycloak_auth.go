package traefik_keycloak_auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Config represents the middleware configuration
type Config struct {
	KeycloakURL string `json:"keycloak_url"` // Keycloak /userinfo endpoint (must be provided)
}

// CreateConfig initializes the default configuration
func CreateConfig() *Config {
	return &Config{}
}

// KeycloakAuthMiddleware is the middleware structure
type KeycloakAuthMiddleware struct {
	next        http.Handler
	keycloakURL string
}

// New creates a new instance of the middleware
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Ensure that the Keycloak URL is provided
	if config.KeycloakURL == "" {
		return nil, fmt.Errorf("keycloak_url is required and must be set in the Traefik configuration")
	}

	return &KeycloakAuthMiddleware{
		next:        next,
		keycloakURL: config.KeycloakURL,
	}, nil
}

// ServeHTTP handles incoming requests and verifies the token
func (m *KeycloakAuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := ""

	// Try to get the token from the URL query parameter (?access_token=XYZ)
	if accessToken := r.URL.Query().Get("access_token"); accessToken != "" {
		token = accessToken
	}

	// If the token is not found in the URL, try to get it from the KEYCLOAK_IDENTITY cookie
	if token == "" {
		cookie, err := r.Cookie("KEYCLOAK_IDENTITY")
		if err == nil {
			token = cookie.Value
		}
	}

	// If no token is found, return 401 Unauthorized
	if token == "" {
		http.Error(w, "Unauthorized: No token provided", http.StatusUnauthorized)
		return
	}

	// Validate the token with Keycloak
	if !m.validateToken(token) {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	// If the token is valid, allow the request to proceed
	m.next.ServeHTTP(w, r)
}

// validateToken checks if the token is valid by calling Keycloak's /userinfo endpoint
func (m *KeycloakAuthMiddleware) validateToken(token string) bool {
	// Create a request to Keycloak's /userinfo endpoint
	req, err := http.NewRequest("GET", m.keycloakURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return false
	}

	// Add the Authorization header with the Bearer token
	req.Header.Set("Authorization", "Bearer "+token)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request to Keycloak:", err)
		return false
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return false
	}

	// Parse the JSON response and check if it contains user data
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		fmt.Println("Error parsing JSON:", err)
		return false
	}

	// If the response contains user data and status is OK, the token is valid
	return resp.StatusCode == http.StatusOK && len(data) > 0
}
