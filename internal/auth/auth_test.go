package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestMakeJWT(t *testing.T) {
	// Test setup
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := 24 * time.Hour

	// Test JWT creation
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Parse and validate the token
	parsedToken, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid) // Parse and validate the token

	// Verify claims
	claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	assert.True(t, ok)
	assert.Equal(t, "chirpy", claims.Issuer)
	assert.Equal(t, userID.String(), claims.Subject)

	// Verify expiration time is set correctly
	expectedExpiry := time.Now().Add(expiresIn)
	assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, 2*time.Second)

	// Verify issued at time is set correctly
	assert.WithinDuration(t, time.Now(), claims.IssuedAt.Time, 2*time.Second)
}

func TestMakeJWT_InvalidSecret(t *testing.T) {
	userID := uuid.New()
	expiresIn := 24 * time.Hour

	// Test with empty secret
	_, err := MakeJWT(userID, "", expiresIn)
	assert.Error(t, err)

	// Test with very long secret
	longSecret := string(make([]byte, 1000))
	_, err = MakeJWT(userID, longSecret, expiresIn)
	assert.NoError(t, err) // Should still work with long secret
}

func TestValidateJWT(t *testing.T) {
	// Test setup
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := 24 * time.Hour

	// Create a valid token
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	assert.NoError(t, err)

	// Test successful validation
	validatedUserID, err := ValidateJWT(token, tokenSecret)
	assert.NoError(t, err)
	assert.Equal(t, userID, validatedUserID)
}

func TestValidateJWT_InvalidToken(t *testing.T) {
	tokenSecret := "test-secret"

	// Test with invalid token string
	_, err := ValidateJWT("invalid-token", tokenSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	// Test setup
	userID := uuid.New()
	tokenSecret := "test-secret"
	wrongSecret := "wrong-secret"
	expiresIn := 24 * time.Hour

	// Create a valid token
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	assert.NoError(t, err)

	// Test with wrong secret
	_, err = ValidateJWT(token, wrongSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	// Test setup
	userID := uuid.New()
	tokenSecret := "test-secret"

	// Create an expired token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		Subject:   userID.String(),
	})

	signedToken, err := token.SignedString([]byte(tokenSecret))
	assert.NoError(t, err)

	// Test expired token
	_, err = ValidateJWT(signedToken, tokenSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")
}

func TestValidateJWT_InvalidClaims(t *testing.T) {
	// Test setup
	tokenSecret := "test-secret"

	// Create a token with invalid claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		Subject:   "invalid-uuid", // Invalid UUID format
	})

	signedToken, err := token.SignedString([]byte(tokenSecret))
	assert.NoError(t, err)

	// Test invalid claims
	_, err = ValidateJWT(signedToken, tokenSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid user ID")
}
