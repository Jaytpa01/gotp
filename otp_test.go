package gotp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The test vectors as described in the RFC: https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
// are documented as having the same secret.
// This was simply wrong, and frankly very annoying to figure out.
// The secrets depend upon the hashing algorithm.
//
// see: https://www.rfc-editor.org/errata_search.php?rfc=6238
var (
	sha1Secret   = []byte("12345678901234567890")
	sha256Secret = []byte("12345678901234567890123456789012")
	sha512Secret = []byte("1234567890123456789012345678901234567890123456789012345678901234")
)

// The default behaviour for an OTP is to generate a TOTP, using
// the SHA1 hashing algorithm.
// We should be able to use the same test cases as totp/totp_test.go and get the same results.
func TestDefaultOTP(t *testing.T) {
	tests := []struct {
		epoch            int64
		expectedTOTP     string
		hashingAlgorithm hashingAlgorithm
		secret           []byte
	}{
		{59, "94287082", SHA1, sha1Secret},
		{59, "46119246", SHA256, sha256Secret},
		{59, "90693936", SHA512, sha512Secret},

		{1111111109, "07081804", SHA1, sha1Secret},
		{1111111109, "68084774", SHA256, sha256Secret},
		{1111111109, "25091201", SHA512, sha512Secret},

		{1111111111, "14050471", SHA1, sha1Secret},
		{1111111111, "67062674", SHA256, sha256Secret},
		{1111111111, "99943326", SHA512, sha512Secret},

		{1234567890, "89005924", SHA1, sha1Secret},
		{1234567890, "91819424", SHA256, sha256Secret},
		{1234567890, "93441116", SHA512, sha512Secret},

		{2000000000, "69279037", SHA1, sha1Secret},
		{2000000000, "90698825", SHA256, sha256Secret},
		{2000000000, "38618901", SHA512, sha512Secret},

		{20000000000, "65353130", SHA1, sha1Secret},
		{20000000000, "77737706", SHA256, sha256Secret},
		{20000000000, "47863826", SHA512, sha512Secret},
	}

	for _, test := range tests {
		otp, err := New(
			"",
			WithDigits(len(test.expectedTOTP)),
			WithHashingAlgorithm(test.hashingAlgorithm),
			WithSecret(test.secret),
		)

		require.NoError(t, err)

		token, err := otp.At(time.Unix(test.epoch, 0)).Generate()
		require.NoError(t, err)

		assert.Equal(t, test.expectedTOTP, token)
	}
}
