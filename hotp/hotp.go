package hotp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

type hotp struct {
	hash   func() hash.Hash
	digits int
}

func New(hash func() hash.Hash, digits int) *hotp {
	return &hotp{
		hash:   hash,
		digits: digits,
	}
}

func (o *hotp) Generate(secret []byte, count int64) string {
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
