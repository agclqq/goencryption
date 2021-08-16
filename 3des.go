package goencryption

// Ecb加密模式 data要加密的数据，key要加密的密钥
func TripleDesECBPkcs7Encrypt(data, key []byte) ([]byte, error) {
	return Encrypt(TriDes,data, key, []byte{}, ECB, Pkcs7)
}

// ECB 模式解密 src密文，key加密时的密钥
func TripleDesECBPkcs7Decrypt(src, key []byte) ([]byte, error) {
	return Decrypt(TriDes,src, key, []byte{}, ECB, Pkcs7)
}

func TripleDesCBCPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(TriDes,data, key, iv, CBC, Pkcs7)
}

func TripleDesCBCPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(TriDes,src, key, iv, CBC, Pkcs7)
}

func TripleDesCFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(TriDes,data, key, iv, CFB, Pkcs7)
}

func TripleDesCFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(TriDes,src, key, iv, CFB, Pkcs7)
}

func TripleDesOFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(TriDes,data, key, iv, OFB, Pkcs7)
}

func TripleDesOFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(TriDes,src, key, iv, OFB, Pkcs7)
}

func TripleDesCTRPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(TriDes,data, key, iv, CTR, Pkcs7)
}

func TripleDesCTRPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(TriDes,src, key, iv, CTR, Pkcs7)
}