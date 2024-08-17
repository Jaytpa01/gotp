package hotp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

type HOTP struct {
	hashingAlgorithm func() hash.Hash
	secret           []byte
	digits           int
	count            int64
}

type Config struct {
	HashingAlgorithm func() hash.Hash
	Secret           []byte
	Digits           int
	Count            int64
}

func New(c Config) *HOTP {
	return &HOTP{
		hashingAlgorithm: c.HashingAlgorithm,
		secret:           c.Secret,
		digits:           c.Digits,
		count:            c.Count,
	}
}

func (o *HOTP) SetCount(c int64) *HOTP {
	o.count = c
	return o
}

func (o *HOTP) Generate() string {
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, uint64(o.count))

	mac := hmac.New(o.hashingAlgorithm, o.secret)
	mac.Write(countBytes)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0xf
	truncatedHash := h[offset : offset+4]
	truncatedHash[0] &= 0x7F

	code := (binary.BigEndian.Uint32(truncatedHash)) % uint32(math.Pow10(o.digits))
	return fmt.Sprintf("%0*d", o.digits, code)
}
