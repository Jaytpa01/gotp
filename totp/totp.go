package totp

import (
	"errors"
	"hash"
	"time"

	"github.com/Jaytpa01/gotp/hotp"
)

type totp struct {
	hash   func() hash.Hash
	digits int
	period int
}

func New(hash func() hash.Hash, digits int, period int) *totp {
	return &totp{
		hash:   hash,
		digits: digits,
		period: period,
	}
}

func (o *totp) validate() error {
	if o.period <= 0 {
		return errors.New("period must be greater than 0")
	}

	return nil
}

func (o *totp) Generate(secret []byte, when time.Time) (string, error) {
	err := o.validate()
	if err != nil {
		return "", err
	}

	count := when.Unix() / int64(o.period)
	token := hotp.New(o.hash, o.digits).Generate(secret, count)
	return token, nil
}
