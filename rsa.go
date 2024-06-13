package goencryption

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// GenKeys Generate both private and public keys
func GenKeys(bits int) ([]byte, []byte, error) {
	//Randomly generates a private key with a specified number of bits
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	X509PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	privateBlock := pem.Block{Type: "PRIVATE KEY", Bytes: X509PrivateKey}
	privateKeyPem := pem.EncodeToMemory(&privateBlock)

	//get PublicKey
	X509PublicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, nil, err
	}
	publicBlock := pem.Block{Type: "PUBLIC KEY", Bytes: X509PublicKey}
	publicKeyPem := pem.EncodeToMemory(&publicBlock)
	return privateKeyPem, publicKeyPem, nil
}

// GenPrvKey Generate private key
func GenPrvKey(bits int) ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	X509PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	rs := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: X509PrivateKey})
	return rs, nil
}

// GenPKCS1PrvKey Generate an RSA private key in PKCS#1 format
func GenPKCS1PrvKey(bits int) ([]byte, error) {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	// 将私钥转换为PKCS#1 ASN.1 DER编码
	prvPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return prvPEM, nil
}

// GenPubKeyFromPrvKey Generate a public key from a private key
func GenPubKeyFromPrvKey(prvKey []byte) ([]byte, error) {
	privateKey, err := parsePrvKey(prvKey)
	if err != nil {
		return nil, err
	}
	//parsePubKey(privateKey.PublicKey)
	X509PublicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}
	rs := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: X509PublicKey})
	return rs, nil
}

// PubKeyEncrypt public key encryption
func PubKeyEncrypt(pubKey, plainText []byte) ([]byte, error) {
	publicKey, err := parsePubKey(pubKey)
	if err != nil {
		return nil, err
	}
	rs, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	return rs, err
}

// PrvKeyDecrypt private key decryption
func PrvKeyDecrypt(prvKey, cipherText []byte) ([]byte, error) {
	privateKey, err := parsePrvKey(prvKey)
	if err != nil {
		return nil, err
	}
	rs, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	return rs, err
}

func parsePrvKey(prvKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(prvKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		key, err := ssh.ParseRawPrivateKey(prvKey)
		if err != nil {
			return nil, err
		}
		rsaPrvKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
		privateKey = rsaPrvKey
	case "RSA PRIVATE KEY":
		v, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		privateKey = v
	default:
		privateKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		v, ok := privateKeyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
		privateKey = v
	}
	return privateKey, nil
}

func detectPubKey(pubKey []byte) []byte {
	// ssh-keygen 生成的公钥
	pub, comment, opt, rest, err := ssh.ParseAuthorizedKey(pubKey)
	_, _, _ = comment, opt, rest
	if err == nil {
		cryptoPubKey, ok := pub.(ssh.CryptoPublicKey)
		if ok {
			rsaPubKey, ok := cryptoPubKey.CryptoPublicKey().(*rsa.PublicKey)
			if ok {
				// 将 RSA 公钥编码为 PKIX 格式
				derBytes, err := x509.MarshalPKIXPublicKey(rsaPubKey)
				if err == nil {
					// 将 PKIX 公钥编码为 PEM 格式
					pemBlock := &pem.Block{
						Type:  "PUBLIC KEY",
						Bytes: derBytes,
					}
					return pem.EncodeToMemory(pemBlock)
				}
			}
		}
	}
	return pubKey
}
func parsePubKey(pubKey []byte) (*rsa.PublicKey, error) {
	pubKey = detectPubKey(pubKey)
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	var publicKey *rsa.PublicKey
	switch block.Type {
	case "RSA PUBLIC KEY":
		v, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		publicKey = v
	default:
		publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		v, ok := publicKeyInterface.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
		publicKey = v
	}
	return publicKey, nil
}

// PrvKeySign private key signature
func PrvKeySign(prvKey, plainText []byte, hash crypto.Hash) ([]byte, error) {
	rsaPrivateKey, err := parsePrvKey(prvKey)
	if err != nil {
		return nil, err
	}

	hashInst := hash.New()
	hashInst.Write(plainText)
	hashByte := hashInst.Sum(nil)

	rs, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, hash, hashByte)
	return rs, err
}

// PubKeyVerifySign public key verification signature
func PubKeyVerifySign(pubKey, plainText, sign []byte, hash crypto.Hash) error {
	publicKey, err := parsePubKey(pubKey)
	if err != nil {
		return err
	}

	hashInst := hash.New()
	hashInst.Write(plainText)
	hashByte := hashInst.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, hash, hashByte, sign)
}
