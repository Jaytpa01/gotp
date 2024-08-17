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
		count        int64
		expectedHOTP string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}

	hotp := hotp.New(hotp.Config{
		HashingAlgorithm: sha1.New,
		Secret:           []byte("12345678901234567890"),
		Digits:           6,
	})

	for _, test := range tests {
		generatedHOTP := hotp.SetCount(test.count).Generate()
		assert.Equal(t, test.expectedHOTP, generatedHOTP)
	}
}
