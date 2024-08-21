package otp

import "crypto/sha1"

const (
	DefaultWindow = 0
	DefaultDigits = 6
	DefaultPeriod = 30
)

var (
	DefaultHashingAlgorithm = sha1.New
)
