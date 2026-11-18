package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

func Bearer(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(header, "Bearer ")
			// Constant-time: a plain != leaks how many leading bytes matched
			// via response timing, which lets an attacker recover the token
			// byte by byte. ConstantTimeCompare is also length-safe (returns
			// 0 on differing lengths) but is only meaningful for a non-empty
			// configured key, so refuse an unset one outright.
			if apiKey == "" || subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) != 1 {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
