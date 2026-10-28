package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
)

func csrfSecret() ([]byte, error) {
	configured := os.Getenv("CSRF_SECRET")
	if configured != "" {
		if len(configured) < 32 {
			return nil, errors.New("CSRF_SECRET must be at least 32 bytes")
		}
		return []byte(configured), nil
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate temporary CSRF secret: %w", err)
	}
	log.Print("CSRF_SECRET is not set; using an ephemeral key (set CSRF_SECRET for deployments)")
	return secret, nil
}
func cookieSecureSetting() (bool, error) {
	value := os.Getenv("COOKIE_SECURE")
	if value == "" {
		return os.Getenv("APP_ENV") == "production", nil
	}
	secure, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("COOKIE_SECURE must be true or false: %w", err)
	}
	return secure, nil
}

func listenAddress() (string, error) {
	if address := os.Getenv("ADDR"); address != "" {
		return address, nil
	}

	port := os.Getenv("PORT")
	if port == "" {
		return ":8080", nil
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("PORT must be a valid TCP port between 1 and 65535")
	}
	return ":" + strconv.Itoa(portNumber), nil
}
