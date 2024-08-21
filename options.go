package gotp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

type option func(*OTP) error

func (o *OTP) applyOpts(opts ...option) error {
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return err
		}
	}

	return nil
}

func WithIssuer(issuer string) option {
	return func(o *OTP) error {
		o.issuer = issuer
		return nil
	}
}

func WithCount(count int64) option {
	return func(o *OTP) error {
		o.count = count
		return nil
	}
}

func WithSecret(secret []byte) option {
	return func(o *OTP) error {
		o.secret = secret
		return nil
	}
}

func WithBase32Secret(s string) option {
	return func(o *OTP) error {
		secret, err := Base32Decode(s)
		if err != nil {
			return fmt.Errorf("failed to decode base32 secret: %w", err)
		}
		o.secret = secret
		return nil
	}
}

func WithHOTP() option {
	return func(o *OTP) error {
		o.algorithm = HOTP
		return nil
	}
}

func WithHashingAlgorithm(ha hashingAlgorithm) option {
	return func(o *OTP) error {
		switch ha {
		case SHA1:
			o.hashingAlgorithm = sha1.New
		case SHA256:
			o.hashingAlgorithm = sha256.New
		case SHA512:
			o.hashingAlgorithm = sha512.New
		default:
			return fmt.Errorf("invalid hashing algorithm: %d", ha)
		}

		return nil
	}
}

func WithPeriod(period int) option {
	return func(o *OTP) error {
		if period <= 0 {
			return fmt.Errorf("period must be greater than 0")
		}

		o.period = period
		return nil
	}
}
