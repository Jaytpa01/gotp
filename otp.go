package gotp

import (
	"crypto/sha1"
	"hash"
	"time"

	"github.com/Jaytpa01/gotp/hotp"
	"github.com/Jaytpa01/gotp/totp"
)

type algorithm int
type hashingAlgorithm int

const (
	TOTP algorithm = iota
	HOTP
)

const (
	SHA1 hashingAlgorithm = iota
	SHA256
	SHA512
)

const (
	DefaultWindow = 0
	DefaultDigits = 6
	DefaultPeriod = 30
)

var DefaultHashingAlgorithm = sha1.New

type otp struct {
	algorithm        algorithm
	hashingAlgorithm func() hash.Hash
	secret           []byte
	digits           int

	// for TOTP
	when   time.Time
	window int
	period int

	// for HOTP
	count int64

	// for URI generation
	accountName string
	issuer      string
}

func New(accountName string, options ...option) (*otp, error) {
	s, err := RandomSecret(20)
	if err != nil {
		return nil, err
	}

	otp := &otp{
		accountName:      accountName,
		algorithm:        TOTP,
		hashingAlgorithm: DefaultHashingAlgorithm,
		secret:           s,
		digits:           DefaultDigits,
		window:           DefaultWindow,
		period:           DefaultPeriod,
	}

	if err := otp.applyOpts(options...); err != nil {
		return nil, err
	}

	return otp, nil
}

func (o *otp) Generate() (string, error) {
	switch o.algorithm {
	case TOTP:
		return o.generateTOTP()

	case HOTP:
		return o.generateHOTP()

	default:
		return "", nil
	}

}

func (o *otp) Secret() []byte {
	return o.secret
}

func (o *otp) Base32Secret() string {
	return Base32Encode(o.secret)
}

func (o *otp) At(time time.Time) *otp {
	o.when = time
	return o
}

func (o *otp) generateTOTP() (string, error) {
	// use the current timestamp for otp generation unless explicitly set otherwise
	when := time.Now()
	if !o.when.IsZero() {
		when = o.when
	}

	return totp.New(o.hashingAlgorithm, o.digits, o.period).Generate(o.secret, when)
}

func (o *otp) generateHOTP() (string, error) {
	return hotp.New(o.hashingAlgorithm, o.digits).Generate(o.secret, o.count), nil
}
