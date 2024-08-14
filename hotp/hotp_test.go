package hotp_test

import (
	"crypto/sha1"
	"testing"

	"github.com/Jaytpa01/gotp/hotp"
	"github.com/stretchr/testify/assert"
)

func TestHOTPGenerate(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/rfc4226#page-32
	tests := []struct {
		count        uint64
		expectedHOTP string
	}{
		{
			count:        0,
			expectedHOTP: "755224",
		},
		{
			count:        1,
			expectedHOTP: "287082",
		},
		{
			count:        2,
			expectedHOTP: "359152",
		},
		{
			count:        3,
			expectedHOTP: "969429",
		},
		{
			count:        4,
			expectedHOTP: "338314",
		},
		{
			count:        5,
			expectedHOTP: "254676",
		},
		{
			count:        6,
			expectedHOTP: "287922",
		},
		{
			count:        7,
			expectedHOTP: "162583",
		},
		{
			count:        8,
			expectedHOTP: "399871",
		},
		{
			count:        9,
			expectedHOTP: "520489",
		},
	}

	secret := []byte("12345678901234567890")
	hotp := hotp.New(hotp.Config{
		HashingAlgorithm: sha1.New,
		Secret:           secret,
		Digits:           6,
	})

	for _, test := range tests {
		generatedHOTP := hotp.SetCount(test.count).Generate()
		assert.Equal(t, test.expectedHOTP, generatedHOTP)
	}
}
