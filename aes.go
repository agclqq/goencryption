package goencryption

// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.

// Ecb加密模式 data要加密的数据，key要加密的密钥
func AesECBPkcs7Encrypt(data, key []byte) ([]byte, error) {
	return Encrypt(Aes,data, key, []byte{}, ECB, Pkcs7)
}

// ECB 模式解密 src密文，key加密时的密钥
func AesECBPkcs7Decrypt(src, key []byte) ([]byte, error) {
	return Decrypt(Aes,src, key, []byte{}, ECB, Pkcs7)
}

func AesCBCPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Aes,data, key, iv, CBC, Pkcs7)
}

func AesCBCPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Aes,src, key, iv, CBC, Pkcs7)
}

func AesCFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Aes,data, key, iv, CFB, Pkcs7)
}

func AesCFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Aes,src, key, iv, CFB, Pkcs7)
}

func AesOFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Aes,data, key, iv, OFB, Pkcs7)
}

func AesOFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Aes,src, key, iv, OFB, Pkcs7)
}

func AesCTRPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Aes,data, key, iv, CTR, Pkcs7)
}

func AesCTRPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Aes,src, key, iv, CTR, Pkcs7)
}
