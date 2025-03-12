package keycloakopenid

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// SecretKey - klucz do podpisywania JWT (powinien być w configu)
var SecretKey = []byte("supersecretkey")

// GenerateJWT - generuje token JWT ważny przez 30 minut
func GenerateJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(30 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(SecretKey)
}

// ValidateJWT - sprawdza poprawność tokena JWT
func ValidateJWT(tokenString string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return SecretKey, nil
	})

	if err != nil {
		return false, fmt.Errorf("błąd walidacji tokena: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		exp, ok := claims["exp"].(float64)
		if !ok || int64(exp) < time.Now().Unix() {
			return false, fmt.Errorf("token wygasł")
		}
		return true, nil
	}

	return false, fmt.Errorf("niepoprawny token")
}
