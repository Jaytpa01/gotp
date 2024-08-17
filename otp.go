package gotp

import "hash"

type OTP struct {
	hashingAlgorithm func() hash.Hash
	secret           []byte

	issuer string
	label  string
}
