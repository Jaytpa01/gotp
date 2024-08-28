package gotp

import (
	"crypto/sha1"
	"hash"
	"net/url"
	"time"

	"github.com/Jaytpa01/gotp/hotp"
	"github.com/Jaytpa01/gotp/totp"
)

type Algorithm int
type HashingAlgorithm int

const (
	TOTP Algorithm = iota
	HOTP
)

const (
	SHA1 HashingAlgorithm = iota
	SHA256
	SHA512
)

const (
	DefaultWindow = 0
	DefaultDigits = 6
	DefaultPeriod = 30
)

var DefaultHashingAlgorithm = sha1.New

type OTP struct {
	algorithm        Algorithm
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

func New(accountName string, options ...option) (*OTP, error) {
	s, err := RandomSecret(20)
	if err != nil {
		return nil, err
	}

	otp := &OTP{
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

func (o *OTP) Generate() (string, error) {
	switch o.algorithm {
	case TOTP:
		return o.generateTOTP()

	case HOTP:
		return o.generateHOTP()

	default:
		return "", nil
	}
}

func (o *OTP) URI() string {
	uri := &url.URL{
		Scheme: "otpauth",
	}

	label := o.accountName
	if o.issuer != "" {
		label = o.issuer + ":" + o.accountName
	}

	q := url.Values{}
	if o.issuer != "" {
		q.Add("issuer", o.issuer)
	}

	return ""
}

func (o *OTP) Secret() []byte {
	return o.secret
}

func (o *OTP) Base32Secret() string {
	return Base32Encode(o.secret)
}

func (o *OTP) At(time time.Time) *OTP {
	o.when = time
	return o
}

func (o *OTP) generateTOTP() (string, error) {
	// use the current timestamp for OTP generation unless explicitly set otherwise
	when := time.Now()
	if !o.when.IsZero() {
		when = o.when
	}

	return totp.New(o.hashingAlgorithm, o.digits, o.period).Generate(o.secret, when)
}

func (o *OTP) generateHOTP() (string, error) {
	return hotp.New(o.hashingAlgorithm, o.digits).Generate(o.secret, o.count), nil
}
