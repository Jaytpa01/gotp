// Package totp implements the Time-based One-Time Password (TOTP) algorithm.
// See https://datatracker.ietf.org/doc/html/rfc6238
package totp

import (
	"errors"
	"hash"
	"time"

	"github.com/Jaytpa01/gotp/hotp"
)

type TOTP struct {
	hash   func() hash.Hash
	digits int
	period int
}

// New initialises a new HOTP generator using the supplied hashing
// function, number of digits, and time period.
func New(hash func() hash.Hash, digits int, period int) *TOTP {
	return &TOTP{
		hash:   hash,
		digits: digits,
		period: period,
	}
}

// Generate generates a TOTP (Time-based One-Time Password) code given
// the shared secret and a time.
func (o *TOTP) Generate(secret []byte, when time.Time) (string, error) {
	err := o.validate()
	if err != nil {
		return "", err
	}

	// get the minimum secret length based on the hashing algorithm used
	minSecretLen := o.hash().Size()
	paddedSecret := padSecret(secret, minSecretLen)

	count := when.Unix() / int64(o.period)
	token := hotp.New(o.hash, o.digits).Generate(paddedSecret, count)
	return token, nil
}

// padSecret pads the secret byte slice by repeating the secret
// until it is the desired length
//
// e.g:
// padSecret([]byte("12345678901234567890"), 32)
// is equal to []byte("12345678901234567890123456789012")
func padSecret(secret []byte, minLength int) []byte {
	secretLength := len(secret)

	if secretLength >= minLength {
		return secret
	}

	paddedSecret := make([]byte, minLength)
	copy(paddedSecret, secret) // copy the secret into the padded secret

	// fill the rest of the padded secret by repeating the
	// supplied secret until it is the desired length
	for i := secretLength; i < minLength; i++ {
		paddedSecret[i] = secret[i%secretLength]
	}

	return paddedSecret
}

func (o *TOTP) validate() error {
	if o.period <= 0 {
		return errors.New("period must be greater than 0")
	}

	return nil
}
