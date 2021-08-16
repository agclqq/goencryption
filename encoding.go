package goencryption

import (
	"encoding/base64"
	"encoding/hex"
)

func Base64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func HexEncode(src []byte) string {
	return hex.EncodeToString(src)
}
func HexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}