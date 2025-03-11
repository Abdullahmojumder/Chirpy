package auth

import (
    "errors"
    "github.com/google/uuid"
    "github.com/stretchr/testify/assert"
    "github.com/golang-jwt/jwt/v5"
    "net/http"
    "testing"
    "time"
)

func TestMakeAndValidateJWT(t *testing.T) {
    userID := uuid.New()
    secret := "mysecretkey"
    expiresIn := 1 * time.Hour

    token, err := MakeJWT(userID, secret, expiresIn)
    assert.NoError(t, err)
    assert.NotEmpty(t, token)

    parsedUserID, err := ValidateJWT(token, secret)
    assert.NoError(t, err)
    assert.Equal(t, userID, parsedUserID)
}

func TestValidateJWTExpired(t *testing.T) {
    userID := uuid.New()
    secret := "mysecretkey"
    expiresIn := -1 * time.Hour // Expired in the past

    token, err := MakeJWT(userID, secret, expiresIn)
    assert.NoError(t, err)

    _, err = ValidateJWT(token, secret)
    assert.Error(t, err)
    assert.ErrorIs(t, err, jwt.ErrTokenExpired) // Check error type
}

func TestValidateJWTWrongSecret(t *testing.T) {
    userID := uuid.New()
    secret := "mysecretkey"
    wrongSecret := "wrongsecretkey"
    expiresIn := 1 * time.Hour

    token, err := MakeJWT(userID, secret, expiresIn)
    assert.NoError(t, err)

    _, err = ValidateJWT(token, wrongSecret)
    assert.Error(t, err)
    assert.ErrorIs(t, err, jwt.ErrSignatureInvalid) // Check error type
}

func TestValidateJWTInvalidToken(t *testing.T) {
    secret := "mysecretkey"
    invalidToken := "invalid.token.string"

    _, err := ValidateJWT(invalidToken, secret)
    assert.Error(t, err)
}


func TestGetBearerToken(t *testing.T) {
    tests := []struct {
        name        string
        headers     http.Header
        expected    string
        expectError bool
        errorMsg    string
    }{
        {
            name: "Valid Bearer Token",
            headers: http.Header{
                "Authorization": []string{"Bearer abc123"},
            },
            expected:    "abc123",
            expectError: false,
        },
        {
            name:        "Missing Header",
            headers:     http.Header{},
            expectError: true,
            errorMsg:    "authorization header missing",
        },
        {
            name: "Invalid Format",
            headers: http.Header{
                "Authorization": []string{"Basic abc123"},
            },
            expectError: true,
            errorMsg:    "invalid authorization header format; expected 'Bearer <token>'",
        },
        {
            name: "Empty Token",
            headers: http.Header{
                "Authorization": []string{"Bearer "},
            },
            expectError: true,
            errorMsg:    "token missing in authorization header",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            token, err := GetBearerToken(tt.headers)
            if tt.expectError {
                assert.Error(t, err)
                assert.Equal(t, tt.errorMsg, err.Error())
                assert.Empty(t, token)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expected, token)
            }
        })
    }
}

