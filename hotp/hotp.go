package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

type HOTP struct {
	hashingAlgorithm func() hash.Hash
	digits           int
}

func New(opts ...option) *HOTP {
	hotp := &HOTP{
		hashingAlgorithm: sha1.New,
		digits:           6,
	}

	hotp.applyOpts(opts...)
	return hotp
}

func (o *HOTP) Generate(secret []byte, count int64) string {
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, uint64(count))

	mac := hmac.New(o.hashingAlgorithm, secret)
	mac.Write(countBytes)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0xf
	truncatedHash := h[offset : offset+4]
	truncatedHash[0] &= 0x7F

	code := (binary.BigEndian.Uint32(truncatedHash)) % uint32(math.Pow10(o.digits))
	return fmt.Sprintf("%0*d", o.digits, code)
}
