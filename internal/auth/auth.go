package auth

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"
    "net/http"
    "strings"
    "time"
)

// GetAPIKey extracts the API key from the Authorization header.
// Expected format: "Authorization: ApiKey THE_KEY_HERE"
func GetAPIKey(headers http.Header) (string, error) {
    authHeader := headers.Get("Authorization")
    if authHeader == "" {
        return "", errors.New("authorization header is missing")
    }

    parts := strings.SplitN(authHeader, " ", 2)
    if len(parts) != 2 || parts[0] != "ApiKey" {
        return "", errors.New("invalid authorization header format; expected 'ApiKey <key>'")
    }

    key := strings.TrimSpace(parts[1])
    if key == "" {
        return "", errors.New("API key is empty")
    }

    return key, nil
}

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
    hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hashedBytes), nil
}

// CheckPasswordHash compares a password with a stored hash.
func CheckPasswordHash(password, hash string) error {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// MakeJWT creates a JWT for a user with the given expiration time.
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
        Issuer:    "chirpy",
        IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
        ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
        Subject:   userID.String(),
    })

    return token.SignedString([]byte(tokenSecret))
}

// ValidateJWT validates a JWT and returns the user ID if valid.
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
    token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, jwt.ErrSignatureInvalid
        }
        return []byte(tokenSecret), nil
    })
    if err != nil {
        return uuid.Nil, err // Return the original error
    }

    claims, ok := token.Claims.(*jwt.RegisteredClaims)
    if !ok {
        return uuid.Nil, jwt.ErrInvalidKey
    }

    userID, err := uuid.Parse(claims.Subject)
    if err != nil {
        return uuid.Nil, err
    }

    return userID, nil
}


// GetBearerToken extracts the JWT from the Authorization header.
func GetBearerToken(headers http.Header) (string, error) {
    authHeader := headers.Get("Authorization")
    if authHeader == "" {
        return "", errors.New("authorization header missing")
    }

    parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || parts[0] != "Bearer" {
        return "", errors.New("invalid authorization header format; expected 'Bearer <token>'")
    }

    token := strings.TrimSpace(parts[1])
    if token == "" {
        return "", errors.New("token missing in authorization header")
    }

    return token, nil
}

func MakeRefreshToken() (string, error) {
    bytes := make([]byte, 32) // 256 bits = 32 bytes
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}
