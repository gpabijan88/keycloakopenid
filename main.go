package keycloakopenid

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// 1️⃣ Sprawdzamy JWT w cookie
	cookie, err := req.Cookie("JWT_AUTH")
	if err == nil {
		// Jeśli cookie istnieje, sprawdzamy poprawność JWT
		valid, err := ValidateJWT(cookie.Value)
		if valid {
			fmt.Println("✅ Poprawny JWT, przepuszczamy request")
			req.Header.Set("Authorization", "Bearer "+cookie.Value) // Przekazujemy JWT dalej
			k.next.ServeHTTP(rw, req)
			return
		}
		fmt.Println("❌ Błąd JWT:", err)
	}

	// 2️⃣ Brak ważnego JWT → uwierzytelnienie w Keycloak
	fmt.Println("🔄 Brak poprawnego JWT, uwierzytelnianie w Keycloak...")
	authCode := req.URL.Query().Get("code")

	if authCode == "" {
		fmt.Printf("code is missing, redirect to Keycloak\n")
		k.redirectToKeycloak(rw, req)
		return
	}

	// 3️⃣ Wymieniamy kod autoryzacyjny na token
	token, err := k.exchangeAuthCode(req, authCode, req.URL.Query().Get("state"))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("✅ Otrzymany token z Keycloak:", token) // Dodaj log do sprawdzenia wartości tokena

	// 4️⃣ Generujemy JWT i zapisujemy w cookie
	jwtToken, err := GenerateJWT("user123") // Możesz przekazać prawdziwe ID użytkownika
	if err != nil {
		http.Error(rw, "Błąd generowania tokena JWT", http.StatusInternalServerError)
		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     "JWT_AUTH",
		Value:    jwtToken,
		Path:     "/",
		Expires:  time.Now().Add(30 * time.Minute),
		HttpOnly: true,
		Secure:   true,
	})

	fmt.Println("✅ Nowy JWT wygenerowany, przepuszczamy request")
	req.Header.Set("Authorization", "Bearer "+jwtToken) // Przekazujemy nowy JWT w headerze

	k.next.ServeHTTP(rw, req)
}

func extractClaims(tokenString string, claimName string) (string, error) {
	jwtContent := strings.Split(tokenString, ".")
	if len(jwtContent) < 3 {
		return "", fmt.Errorf("malformed jwt")
	}

	var jwtClaims map[string]interface{}
	decoder := base64.StdEncoding.WithPadding(base64.NoPadding)

	jwt_bytes, _ := decoder.DecodeString(jwtContent[1])
	if err := json.Unmarshal(jwt_bytes, &jwtClaims); err != nil {
		return "", err
	}

	if claimValue, ok := jwtClaims[claimName]; ok {
		return fmt.Sprintf("%v", claimValue), nil
	}
	return "", fmt.Errorf("missing claim %s", claimName)
}

func (k *keycloakAuth) exchangeAuthCode(req *http.Request, authCode string, stateBase64 string) (string, error) {
	stateBytes, _ := base64.StdEncoding.DecodeString(stateBase64)
	var state state
	err := json.Unmarshal(stateBytes, &state)
	if err != nil {
		return "", err
	}

	target := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"token",
	)
	resp, err := http.PostForm(target.String(),
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {k.ClientID},
			"client_secret": {k.ClientSecret},
			"code":          {authCode},
			"redirect_uri":  {state.RedirectURL},
		})

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.New("received bad response from Keycloak: " + string(body))
	}

	var tokenResponse KeycloakTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

func (k *keycloakAuth) redirectToKeycloak(rw http.ResponseWriter, req *http.Request) {
	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

	state := state{
		RedirectURL: originalURL,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	redirectURL := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"auth",
	)
	redirectURL.RawQuery = url.Values{
		"response_type": {"code"},
		"client_id":     {k.ClientID},
		"redirect_uri":  {originalURL},
		"state":         {stateBase64},
		"scope":         {k.Scope},
	}.Encode()

	http.Redirect(rw, req, redirectURL.String(), http.StatusTemporaryRedirect)
}

func (k *keycloakAuth) verifyToken(token string) (bool, error) {
	client := &http.Client{}

	data := url.Values{
		"token": {token},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		k.KeycloakURL.JoinPath(
			"realms",
			k.KeycloakRealm,
			"protocol",
			"openid-connect",
			"token",
			"introspect",
		).String(),
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(k.ClientID, k.ClientSecret)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var introspectResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&introspectResponse)
	if err != nil {
		return false, err
	}

	return introspectResponse["active"].(bool), nil
}
