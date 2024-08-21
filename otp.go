package gotp

import (
	"hash"
	"time"

	"github.com/Jaytpa01/gotp/hotp"
	"github.com/Jaytpa01/gotp/internal/otp"
	"github.com/Jaytpa01/gotp/totp"
)

type algorithm int

const (
	TOTP algorithm = iota
	HOTP
)

type hashingAlgorithm int

const (
	SHA1 hashingAlgorithm = iota
	SHA256
	SHA512
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
	s, err := RandomSecret(20)
	if err != nil {
		return nil, err
	}

	otp := &OTP{
		accountName:      accountName,
		secret:           s,
		algorithm:        TOTP,
		hashingAlgorithm: otp.DefaultHashingAlgorithm,
		digits:           otp.DefaultDigits,
		window:           otp.DefaultWindow,
		period:           otp.DefaultPeriod,
	}

	if err := otp.applyOpts(options...); err != nil {
		return nil, err
	}

	return otp, nil
}

func (o *OTP) Generate() string {
	switch o.algorithm {
	case TOTP:
		return o.generateTOTP()

	case HOTP:
		return o.generateHOTP()

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

func (o *OTP) generateTOTP() string {
	return totp.New(
		totp.WithHashingAlgorithm(o.hashingAlgorithm),
		totp.WithWindow(o.window),
		totp.WithDigits(o.digits),
		totp.WithPeriod(o.period),
	).Generate(o.secret, time.Now())
}

func (o *OTP) generateHOTP() string {
	return hotp.New(
		hotp.WithHashingAlgorithm(o.hashingAlgorithm),
		hotp.WithDigits(o.digits),
	).Generate(o.secret, o.count)
}
