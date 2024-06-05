package goencryption

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	//publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
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

	privateBlock := pem.Block{Type: "PRIVATE KEY", Bytes: X509PrivateKey}
	rs := pem.EncodeToMemory(&privateBlock)
	return rs, nil
}

// GenPubKeyFromPrvKey Generate a public key from a private key
func GenPubKeyFromPrvKey(prvKey []byte) ([]byte, error) {
	block, _ := pem.Decode(prvKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rasPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	publicKey := rasPrivateKey.Public()
	X509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	publicBlock := pem.Block{Type: "PUBLIC KEY", Bytes: X509PublicKey}
	rs := pem.EncodeToMemory(&publicBlock)
	return rs, nil
}

// PubKeyEncrypt public key encryption
func PubKeyEncrypt(pubKey, plainText []byte) ([]byte, error) {
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
	rs, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	return rs, err
}

// PrvKeyDecrypt private key decryption
func PrvKeyDecrypt(prvKey, cipherText []byte) ([]byte, error) {
	block, _ := pem.Decode(prvKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "RAS PUBLIC KEY":
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
	rs, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	return rs, err
}

// PrvKeySign private key signature
func PrvKeySign(prvKey, plainText []byte, hash crypto.Hash) ([]byte, error) {
	block, _ := pem.Decode(prvKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 进行类型断言，确保是 RSA 私钥
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	hashInst := hash.New()
	hashInst.Write(plainText)
	hashByte := hashInst.Sum(nil)

	rs, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, hash, hashByte)
	return rs, err
}

// PubKeyVerifySign public key verification signature
func PubKeyVerifySign(pubKey, plainText, sign []byte, hash crypto.Hash) error {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block containing public key")
	}
	var publicKey *rsa.PublicKey
	if block.Type == "RSA PUBLIC KEY" {
		v, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return err
		}
		publicKey = v
	} else {
		publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		v, ok := publicKeyInterface.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("not an RSA public key")
		}
		publicKey = v
	}

	hashInst := hash.New()
	hashInst.Write(plainText)
	hashByte := hashInst.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, hash, hashByte, sign)
}
