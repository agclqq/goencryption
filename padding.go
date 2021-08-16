package goencryption

import "bytes"

func Pkcs7Padding(text []byte, blockSize int) []byte {
	paddingSize := blockSize - len(text)%blockSize
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(text, paddingText...)
}
func Pkcs7UnPadding(src []byte) []byte {
	n := len(src)
	if n==0{
		return src
	}
	count := int(src[n-1])
	text := src[:n-count]
	return text
}
func Pkcs5Padding(text []byte)[]byte  {
	return Pkcs7Padding(text,8)
}
func Pkcs5UnPadding(src []byte)[]byte  {
	return Pkcs7UnPadding(src)
}
func ZeroPadding(text []byte, blockSize int) []byte{
	paddingSize := blockSize - len(text)%blockSize
	paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize)
	return append(text, paddingText...)
}
func ZeroUnPadding(src []byte)[]byte  {
	return bytes.TrimRight(src,string([]byte{0}))
}