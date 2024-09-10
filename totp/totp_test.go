package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
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

func TestTOTPGenerate(t *testing.T) {
	tests := []struct {
		epoch            int64
		expectedTOTP     string
		hashingAlgorithm func() hash.Hash
		secret           []byte
	}{
		{59, "94287082", sha1.New, sha1Secret},
		{59, "46119246", sha256.New, sha256Secret},
		{59, "90693936", sha512.New, sha512Secret},

		{1111111109, "07081804", sha1.New, sha1Secret},
		{1111111109, "68084774", sha256.New, sha256Secret},
		{1111111109, "25091201", sha512.New, sha512Secret},

		{1111111111, "14050471", sha1.New, sha1Secret},
		{1111111111, "67062674", sha256.New, sha256Secret},
		{1111111111, "99943326", sha512.New, sha512Secret},

		{1234567890, "89005924", sha1.New, sha1Secret},
		{1234567890, "91819424", sha256.New, sha256Secret},
		{1234567890, "93441116", sha512.New, sha512Secret},

		{2000000000, "69279037", sha1.New, sha1Secret},
		{2000000000, "90698825", sha256.New, sha256Secret},
		{2000000000, "38618901", sha512.New, sha512Secret},

		{20000000000, "65353130", sha1.New, sha1Secret},
		{20000000000, "77737706", sha256.New, sha256Secret},
		{20000000000, "47863826", sha512.New, sha512Secret},
	}

	for _, test := range tests {
		otp, err := New(test.hashingAlgorithm, len(test.expectedTOTP), 30).Generate(test.secret, time.Unix(test.epoch, 0))
		require.NoError(t, err)
		assert.Equal(t, test.expectedTOTP, otp)
	}
}

// As mentioned in the top of this test file, the supplied test vectors were wrong.
// This was confusing, and caused the tests to fail before adding the other secrets - this was before totp secret padding was implemented.
// As we now pad the supplied secret by repeating it until the expected length,
// we should now be able to get similar tests to TestTOTPGenerate to pass, but
// only specify one secret.
func TestTOTPGenerateWithPadding(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := []struct {
		epoch            int64
		expectedTOTP     string
		hashingAlgorithm func() hash.Hash
	}{
		{59, "94287082", sha1.New},
		{59, "46119246", sha256.New},
		{59, "90693936", sha512.New},

		{1111111109, "07081804", sha1.New},
		{1111111109, "68084774", sha256.New},
		{1111111109, "25091201", sha512.New},

		{1111111111, "14050471", sha1.New},
		{1111111111, "67062674", sha256.New},
		{1111111111, "99943326", sha512.New},

		{1234567890, "89005924", sha1.New},
		{1234567890, "91819424", sha256.New},
		{1234567890, "93441116", sha512.New},

		{2000000000, "69279037", sha1.New},
		{2000000000, "90698825", sha256.New},
		{2000000000, "38618901", sha512.New},

		{20000000000, "65353130", sha1.New},
		{20000000000, "77737706", sha256.New},
		{20000000000, "47863826", sha512.New},
	}

	for _, test := range cases {
		otp, err := New(test.hashingAlgorithm, len(test.expectedTOTP), 30).Generate(secret, time.Unix(test.epoch, 0))
		require.NoError(t, err)
		assert.Equal(t, test.expectedTOTP, otp)
	}
}

func TestPadSecret(t *testing.T) {
	tests := []struct {
		secret         []byte
		expectedSecret []byte
		minLength      int
	}{
		{[]byte("12345678901234567890"), []byte("12345678901234567890"), 20},
		{[]byte("12345678901234567890"), []byte("12345678901234567890123456789012"), 32},
		{[]byte("12345678901234567890"), []byte("1234567890123456789012345678901234567890123456789012345678901234"), 64},
	}

	for i, test := range tests {
		paddedSecret := padSecret(test.secret, test.minLength)
		assert.Equal(t, test.expectedSecret, paddedSecret, "test %d\tsecret length: %d\texpected length: %d", i, len(test.secret), len(test.expectedSecret))
	}
}
