package totp

import (
	"hash"
	"time"

	"github.com/Jaytpa01/gotp/hotp"
)

type TOTP struct {
	hashingAlgorithm func() hash.Hash
	secret           []byte
	digits           int
	time             time.Time
	period           int
	window           int
}

type Config struct {
	HashingAlgorithm func() hash.Hash
	Secret           []byte
	Digits           int
	Time             time.Time
	Period           int
	Window           int
}

func New(c Config) *TOTP {
	return &TOTP{
		hashingAlgorithm: c.HashingAlgorithm,
		secret:           c.Secret,
		digits:           c.Digits,
		time:             c.Time,
		period:           c.Period,
		window:           c.Window,
	}
}

func (o *TOTP) At(t time.Time) *TOTP {
	o.time = t
	return o
}

func (o *TOTP) Generate() string {
	hotp := hotp.New(hotp.Config{
		HashingAlgorithm: o.hashingAlgorithm,
		Secret:           o.secret,
		Digits:           o.digits,
		Count:            o.time.Unix() / int64(o.period),
	})

	return hotp.Generate()
}
