package gotp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
)

type option func(*otp) error

func (o *otp) applyOpts(opts ...option) error {
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return err
		}
	}

	return nil
}

func WithIssuer(issuer string) option {
	return func(o *otp) error {
		o.issuer = issuer
		return nil
	}
}

func WithCount(count int64) option {
	return func(o *otp) error {
		o.count = count
		return nil
	}
}

func WithSecret(secret []byte) option {
	return func(o *otp) error {
		o.secret = secret
		return nil
	}
}

func WithBase32Secret(s string) option {
	return func(o *otp) error {
		secret, err := Base32Decode(s)
		if err != nil {
			return fmt.Errorf("failed to decode base32 secret: %w", err)
		}
		o.secret = secret
		return nil
	}
}

func WithHOTP() option {
	return func(o *otp) error {
		o.algorithm = HOTP
		return nil
	}
}

func WithHashingAlgorithm(ha hashingAlgorithm) option {
	return func(o *otp) error {
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
	return func(o *otp) error {
		if period <= 0 {
			return errors.New("period must be greater than 0")
		}

		o.period = period
		return nil
	}
}

func WithDigits(digits int) option {
	return func(o *otp) error {
		if digits <= 0 {
			return errors.New("digits must be greater than 0")
		}

		o.digits = digits
		return nil
	}
}
