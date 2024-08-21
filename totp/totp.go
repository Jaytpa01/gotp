package totp

import (
	"hash"
	"time"

	"github.com/Jaytpa01/gotp/hotp"
	"github.com/Jaytpa01/gotp/internal/otp"
)

type TOTP struct {
	hashingAlgorithm func() hash.Hash
	digits           int
	period           int
	window           int
}

func New(opts ...option) *TOTP {
	totp := &TOTP{
		hashingAlgorithm: otp.DefaultHashingAlgorithm,
		digits:           otp.DefaultDigits,
		period:           otp.DefaultPeriod,
		window:           otp.DefaultWindow,
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
