package gotp

import "hash"

type OTP struct {
	algorithm        OTPer
	hashingAlgorithm func() hash.Hash
	secret           []byte

	issuer string
	label  string
}

type OTPer interface {
	Generator
	Verifier
}

type Generator interface {
	Generate() string
}

type Verifier interface {
	Verify(string) bool
}
