package gotp

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"image/png"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Jaytpa01/gotp/hotp"
	"github.com/Jaytpa01/gotp/totp"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
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
	DefaultWindow           = 0
	DefaultDigits           = 6
	DefaultPeriod           = 30
	DefaultHashingAlgorithm = SHA1
)

func (h HashingAlgorithm) String() string {
	switch h {
	case SHA1:
		return "SHA1"
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	default:
		return "unknown"

	}
}

type OTP struct {
	algorithm Algorithm
	ha        HashingAlgorithm
	secret    []byte
	digits    int

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

// New returns a new *OTP. If no secret has been supplied
// by an option, one will be automatically generated
func New(accountName string, options ...option) (*OTP, error) {
	otp := &OTP{
		accountName: accountName,
		algorithm:   TOTP,
		ha:          DefaultHashingAlgorithm,
		digits:      DefaultDigits,
		window:      DefaultWindow,
		period:      DefaultPeriod,
	}

	if err := otp.applyOpts(options...); err != nil {
		return nil, err
	}

	// if no secret was supplied, lets generate one here
	if otp.secret == nil {
		// we get the hashing func
		hashFunc := hashFuncFromAlgorithm(otp.ha)
		secretSize := hashFunc().Size()

		s, err := RandomSecret(secretSize)
		if err != nil {
			return nil, err
		}

		otp.secret = s
	}

	return otp, nil
}

// Generate will generate an OTP
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

// URI returns the provisioning uri for Authenticator apps.
// These are normally displayed as QR Codes to an end user
func (o *OTP) URI() string {
	uri := &url.URL{
		Scheme: "otpauth",
		Host:   o.Algorithm(),
	}

	label := o.accountName
	if o.issuer != "" {
		label = o.issuer + ":" + o.accountName
	}

	uri.Path = label

	q := url.Values{}
	q.Add("digits", strconv.Itoa(o.digits))
	q.Add("secret", o.Base32Secret())
	q.Add("algorithm", o.hashingAlgorithm())

	if o.issuer != "" {
		q.Add("issuer", o.issuer)
	}

	if o.algorithm == TOTP {
		q.Add("period", strconv.Itoa(o.period))
	} else if o.algorithm == HOTP {
		q.Add("count", strconv.FormatInt(o.count, 10))
	}

	// the Google Authenticator key URI format expects
	// that space characters are encoded as %20 instead of +.
	// Golangs url.QueryEscape() and url.Values.Encode()
	// both encode the space char as +.
	// see:
	// - https://github.com/google/google-authenticator/wiki/Key-Uri-Format#issuer
	// - https://github.com/golang/go/issues/4013
	// - https://groups.google.com/g/golang-nuts/c/BB443qEjPIk
	uri.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")

	return uri.String()
}

// QRCode generates a QR code representation of the OTP key URI as a byte slice.
func (o *OTP) QRCode() ([]byte, error) {
	qrCode, err := qr.Encode(o.URI(), qr.M, qr.Auto)
	if err != nil {
		return nil, fmt.Errorf("couldn't encode uri to qr code: %w", err)
	}

	qrCode, err = barcode.Scale(qrCode, 150, 150)
	if err != nil {
		return nil, fmt.Errorf("couldn't encode uri to qr code: %w", err)
	}

	buf := new(bytes.Buffer)
	if err := png.Encode(buf, qrCode); err != nil {
		return nil, fmt.Errorf("couldn't generate qr code: %w", err)
	}

	return buf.Bytes(), nil
}

// Secret returns the secret as a byte slice
func (o *OTP) Secret() []byte {
	return o.secret
}

// Base32 returns the secret in base32
func (o *OTP) Base32Secret() string {
	return Base32Encode(o.secret)
}

// At sets the time an OTP will be generated for
func (o *OTP) At(time time.Time) *OTP {
	o.when = time
	return o
}

func (o *OTP) hashingAlgorithm() string {
	return o.ha.String()
}

func (o *OTP) Algorithm() string {
	switch o.algorithm {
	case TOTP:
		return "totp"
	case HOTP:
		return "hotp"
	default:
		return "unknown"
	}
}

func (o *OTP) generateTOTP() (string, error) {
	// use the current timestamp for OTP generation unless explicitly set otherwise
	when := time.Now()
	if !o.when.IsZero() {
		when = o.when
	}

	return totp.New(hashFuncFromAlgorithm(o.ha), o.digits, o.period).Generate(o.secret, when)
}

func (o *OTP) generateHOTP() (string, error) {
	return hotp.New(hashFuncFromAlgorithm(o.ha), o.digits).Generate(o.secret, o.count), nil
}

// hashFuncFromAlgorithm returns the actual `func() hash.Hash` we need to generate OTPs
// from our internal `gotp.HashingAlgorithm` type
func hashFuncFromAlgorithm(ha HashingAlgorithm) func() hash.Hash {
	switch ha {
	case SHA1:
		return sha1.New
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	default:
		return sha1.New
	}
}
