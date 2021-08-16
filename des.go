package goencryption

// Ecb加密模式 data要加密的数据，key要加密的密钥
func DesECBPkcs7Encrypt(data, key []byte) ([]byte, error) {
	return Encrypt(Des,data, key, []byte{}, ECB, Pkcs7)
}

// ECB 模式解密 src密文，key加密时的密钥
func DesECBPkcs7Decrypt(src, key []byte) ([]byte, error) {
	return Decrypt(Des,src, key, []byte{}, ECB, Pkcs7)
}

func DesCBCPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Des,data, key, iv, CBC, Pkcs7)
}

func DescCBCPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Des,src, key, iv, CBC, Pkcs7)
}

func DesCFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Des,data, key, iv, CFB, Pkcs7)
}

func DesCFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Des,src, key, iv, CFB, Pkcs7)
}

func DesOFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Des,data, key, iv, OFB, Pkcs7)
}

func DesOFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Des,src, key, iv, OFB, Pkcs7)
}

func DesCTRPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Des,data, key, iv, CTR, Pkcs7)
}

func DesCTRPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Des,src, key, iv, CTR, Pkcs7)
}
