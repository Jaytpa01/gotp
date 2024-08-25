package totp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPadSecret(t *testing.T) {
	tests := []struct {
		secret         []byte
		expectedSecret []byte
		minLength      int
	}{
		{[]byte("12345678901234567890"), []byte("12345678901234567890"), 20},
		{[]byte("12345678901234567890"), []byte("12345678901234567890123456789012"), 32},
		{[]byte("12345678901234567890"), []byte("1234567890123456789012345678901234567890123456789012345678901234"), 64},
	}

	for i, test := range tests {
		paddedSecret := padSecret(test.secret, test.minLength)
		assert.Equal(t, test.expectedSecret, paddedSecret, "test %d\tsecret lenght: %d\texpected length: %d", i, len(test.secret), len(test.expectedSecret))
	}
}
