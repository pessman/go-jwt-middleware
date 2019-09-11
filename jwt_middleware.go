package jwtmiddleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

func Message(message string) map[string]interface{} {
	return map[string]interface{}{"message": message}
}

func Respond(w http.ResponseWriter, status int, data map[string]interface{}) {
	w.WriteHeader(status)
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

var JwtMiddleware = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := make(map[string]interface{})
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			response = Message("Missing auth token.")
			Respond(w, http.StatusForbidden, response)
			return
		}

		splitAuthHeader := strings.Split(authHeader, "Bearer ")
		if len(splitAuthHeader) != 2 {
			response = Message("Invalid/Malformed auth token. Authorization Header must contain Bearer token.")
			Respond(w, http.StatusForbidden, response)
			return
		}

		authToken := splitAuthHeader[1]
		token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v.", token.Header["alg"])
			}

			return []byte(os.Getenv("token_password")), nil
		})

		if err != nil {
			response = Message(fmt.Sprintf("Malformed authorization token. %v", err.Error()))
			Respond(w, http.StatusForbidden, response)
			return
		}

		if !token.Valid {
			response = Message("Authorization token is not valid.")
			Respond(w, http.StatusForbidden, response)
			return
		}

		next.ServeHTTP(w, r)
	})
}
