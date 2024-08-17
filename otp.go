package gotp

import (
	"crypto/sha1"
	"hash"
	"time"

	"github.com/Jaytpa01/gotp/hotp"
	"github.com/Jaytpa01/gotp/totp"
)

type algorithm int

const (
	TOTP algorithm = iota
	HOTP
)

type OTP struct {
	algorithm        algorithm
	hashingAlgorithm func() hash.Hash
	digits           int
	secret           []byte

	window int
	period int
	count  int64

	issuer      string
	accountName string
}

func New(accountName string, options ...option) (*OTP, error) {
	defaultSecret, err := RandomSecret(20)
	if err != nil {
		return nil, err
	}

	otp := &OTP{
		algorithm:        TOTP,
		hashingAlgorithm: sha1.New,
		secret:           defaultSecret,
		window:           0,
		count:            0,
		issuer:           "",
		accountName:      accountName,
	}

	if err := otp.applyOpts(options...); err != nil {
		return nil, err
	}

	return otp, nil
}

func (o *OTP) Generate() string {
	switch o.algorithm {
	case TOTP:
		return totp.New(
			totp.WithHashingAlgorithm(o.hashingAlgorithm),
			totp.WithWindow(o.window),
			totp.WithDigits(o.digits),
			totp.WithPeriod(o.period),
		).Generate(o.secret, time.Now())

	case HOTP:
		return hotp.New(
			hotp.WithHashingAlgorithm(o.hashingAlgorithm),
			hotp.WithDigits(o.digits),
		).Generate(o.secret, o.count)

	default:
		return ""
	}
}

func (o *OTP) Secret() []byte {
	return o.secret
}

func (o *OTP) SecretBase32() string {
	return Base32Encode(o.secret)
}
