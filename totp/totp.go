package totp

import (
	"crypto/sha1"
	"hash"
	"time"

	"github.com/Jaytpa01/gotp/hotp"
)

type TOTP struct {
	hashingAlgorithm func() hash.Hash
	digits           int
	period           int
	window           int
}

func New(opts ...option) *TOTP {
	totp := &TOTP{
		hashingAlgorithm: sha1.New,
		digits:           6,
		period:           30,
		window:           0,
	}

	totp.applyOpts(opts...)
	return totp
}

func (o *TOTP) Generate(secret []byte, when time.Time) string {
	hotp := hotp.New(
		hotp.WithHashingAlgorithm(o.hashingAlgorithm),
		hotp.WithDigits(o.digits),
	)

	count := when.Unix() / int64(o.period)
	return hotp.Generate(secret, count)
}
