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
	count            uint64
}

type Config struct {
	HashingAlgorithm func() hash.Hash
	Secret           []byte
	Digits           int
	Count            uint64
}

func New(cfg Config) *HOTP {
	return &HOTP{
		hashingAlgorithm: cfg.HashingAlgorithm,
		secret:           cfg.Secret,
		digits:           cfg.Digits,
		count:            cfg.Count,
	}
}

func (o *HOTP) SetCount(c uint64) *HOTP {
	o.count = c
	return o
}

func (o *HOTP) Generate() string {
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, o.count)

	mac := hmac.New(o.hashingAlgorithm, o.secret)
	mac.Write(countBytes)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0xf
	truncatedHash := h[offset : offset+4]
	truncatedHash[0] &= 0x7F

	code := (binary.BigEndian.Uint32(truncatedHash)) % uint32(math.Pow10(o.digits))
	return fmt.Sprintf("%0*d", o.digits, code)
}
