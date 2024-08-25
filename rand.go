package gotp

import (
	"crypto/rand"
	"fmt"
)

func RandomSecret(length int) ([]byte, error) {
	b := make([]byte, length)
	n, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random secret: %w", err)
	}

	if n != length {
		return nil, fmt.Errorf("failed to generate random secret: read %d bytes, expected %d", n, length)
	}

	return b, nil
}
