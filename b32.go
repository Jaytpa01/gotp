package gotp

import "encoding/base32"

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func Base32Encode(data []byte) string {
	return b32.EncodeToString(data)
}

func Base32Decode(s string) ([]byte, error) {
	return b32.DecodeString(s)
}
