package totp_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
	"time"

	"github.com/Jaytpa01/gotp/totp"
	"github.com/stretchr/testify/assert"
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
		epoch            int
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
		totp := totp.New(totp.Config{
			HashingAlgorithm: test.hashingAlgorithm,
			Secret:           test.secret,
			Digits:           8,
			Period:           30,
			Time:             time.Unix(int64(test.epoch), 0),
		})

		assert.Equal(t, test.expectedTOTP, totp.Generate())
	}
}
