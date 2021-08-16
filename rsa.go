package goencryption

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

//Generate both private and public keys
func GenKeys(bits int) ([]byte, []byte, error) {
	//Randomly generates a private key with a specified number of bits
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}
	rsPrivateKey := pem.EncodeToMemory(&privateBlock)

	//get PublicKey
	publicKey := privateKey.PublicKey
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, nil, err
	}
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}
	rsPublicBlock := pem.EncodeToMemory(&publicBlock)
	return rsPrivateKey, rsPublicBlock, nil
}

//Generate private key
func GenPrvKey(bits int) ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}
	rs := pem.EncodeToMemory(&privateBlock)
	return rs, nil
}

//Generate a public key from a private key
func GenPubKeyFromPrvKey(prvKey []byte) ([]byte, error) {
	block, _ := pem.Decode(prvKey)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.PublicKey
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, err
	}

	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}
	rs := pem.EncodeToMemory(&publicBlock)
	return rs, nil
}

//public key encryption
func PubKeyEncrypt(pubKey, msg []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKey)
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	rs, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, msg)
	return rs, err
}
//private key decryption
func PrvKeyDecrypt(prvKey, cipherText []byte) ([]byte, error) {
	block, _ := pem.Decode(prvKey)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rs, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	return rs, err
}

//private key signature
func PrvKeySign(prvKey, msg []byte, hash crypto.Hash) ([]byte, error) {
	block, _ := pem.Decode(prvKey)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	hashInst := hash.New()
	hashInst.Write(msg)
	hashByte := hashInst.Sum(nil)

	rs, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashByte)
	return rs, err
}
//public key verification signature
func PubKeyVerifySign(pubKey, msg, sign []byte, hash crypto.Hash) error {
	block, _ := pem.Decode(pubKey)
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	hashInst := hash.New()
	hashInst.Write(msg)
	hashByte := hashInst.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, hash, hashByte, sign)
}
