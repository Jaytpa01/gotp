package gotp

import (
	"fmt"
	"hash"
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

func WithHashingAlgorithm(hashingAlgorithm func() hash.Hash) option {
	return func(o *OTP) error {
		o.hashingAlgorithm = hashingAlgorithm
		return nil
	}
}
