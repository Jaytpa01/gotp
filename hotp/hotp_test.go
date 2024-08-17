package hotp_test

import (
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

	for _, test := range tests {
		generatedHOTP := hotp.New().Generate([]byte("12345678901234567890"), test.count)
		assert.Equal(t, test.expectedHOTP, generatedHOTP)
	}
}
