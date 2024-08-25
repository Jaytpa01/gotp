// Package hotp implements the HMAC-based One-Time Password (HOTP) algorithm.
// See https://datatracker.ietf.org/doc/html/rfc4226
package hotp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

type HOTP struct {
	hash   func() hash.Hash
	digits int
}

// New initialises a new HOTP generator using the supplied hashing
// function and number of digits.
func New(hash func() hash.Hash, digits int) *HOTP {
	return &HOTP{
		hash:   hash,
		digits: digits,
	}
}

// Generate generates a HOTP (HMAC-based One-Time Password) code given
// the shared secret and count.
func (o *HOTP) Generate(secret []byte, count int64) string {
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, uint64(count))

	mac := hmac.New(o.hash, secret)
	mac.Write(countBytes)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0xf
	truncatedHash := h[offset : offset+4]
	truncatedHash[0] &= 0x7F

	code := (binary.BigEndian.Uint32(truncatedHash)) % uint32(math.Pow10(o.digits))
	return fmt.Sprintf("%0*d", o.digits, code)
}
