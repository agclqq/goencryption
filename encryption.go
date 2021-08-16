package goencryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"errors"
	"fmt"
	"strings"
)

type cryptoType int
type mode int
type padding int
type transcode int

const (
	Aes cryptoType = iota
	Des
	TriDes
)

const (
	ECB mode = iota
	CBC
	CFB
	OFB
	CTR
)

const (
	No padding = iota
	Zero
	Pkcs5
	Pkcs7
)

const (
	Base64 transcode = iota
	Hex
)

func Encrypt(multiple cryptoType, plainText, key, iv []byte, mode mode, padding padding) ([]byte, error) {
	var block cipher.Block
	var err error

	switch multiple {
	case Aes:
		//The key argument should be the AES key,
		// either 16, 24, or 32 bytes to select
		// AES-128, AES-192, or AES-256.
		block, err = aes.NewCipher(key)
	case Des:
		block, err = des.NewCipher(key)
	case TriDes:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()

	var plainPadding []byte
	switch padding {
	case Zero:
		plainPadding = ZeroPadding(plainText, bs)
	case Pkcs5:
		plainPadding = Pkcs5Padding(plainText)
	case Pkcs7:
		plainPadding = Pkcs7Padding(plainText, bs)
	default:
		plainPadding=plainText
	}
	if len(plainPadding)%bs != 0 {
		return nil, errors.New(fmt.Sprintf("the length of the completed data must be an integer multiple of the block, the completed data size is %d, block size is %d", len(plainPadding), bs))
	}

	cryptText := make([]byte, len(plainPadding))
	switch mode {
	case ECB:
		dst := cryptText
		for len(plainPadding) > 0 {
			//Encrypt加密第一个块，将其结果保存到dst
			block.Encrypt(dst, plainPadding[:bs])
			plainPadding = plainPadding[bs:]
			dst = dst[bs:]
		}
	case CBC:
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(cryptText, plainPadding)
	case CFB:
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(cryptText, plainPadding)
	case OFB:
		cipher.NewOFB(block, iv).XORKeyStream(cryptText, plainPadding)
	case CTR:
		cipher.NewCTR(block, iv).XORKeyStream(cryptText, plainPadding)
	}

	return cryptText, nil
}

func Decrypt(multiple cryptoType, cipherText, key, iv []byte, mode mode, padding padding) ([]byte, error) {
	var block cipher.Block
	var err error

	switch multiple {
	case Aes:
		block, err = aes.NewCipher(key)
	case Des:
		block, err = des.NewCipher(key)
	case TriDes:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(cipherText)%bs != 0 {
		return nil, errors.New(fmt.Sprintf("improper decrypt type, block size is %d", bs))
	}

	dst := make([]byte, len(cipherText))

	switch mode {
	case ECB:
		dstTmp := dst
		for len(cipherText) > 0 {
			block.Decrypt(dstTmp, cipherText[:bs])
			cipherText = cipherText[bs:]
			dstTmp = dstTmp[bs:]
		}
	case CBC:
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, cipherText)
	case CFB:
		cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, cipherText)
	case OFB:
		cipher.NewOFB(block, iv).XORKeyStream(dst, cipherText)
	case CTR:
		cipher.NewCTR(block, iv).XORKeyStream(dst, cipherText)
	}

	switch padding {
	case Zero:
		dst = ZeroUnPadding(dst)
	case Pkcs5:
		dst = Pkcs5UnPadding(dst)
	case Pkcs7:
		dst = Pkcs7UnPadding(dst)
	}
	return dst, nil
}

// easyType:cryptoType/mode/padding/transcode
func EasyEncrypt(easyType, plainText, key, iv string) (string, error) {
	c, m, p, t, err := easyCheck(easyType)
	if err != nil {
		return "", err
	}

	rs, err := Encrypt(c, []byte(plainText), []byte(key), []byte(iv), m, p)
	if err != nil {
		return "", err
	}

	switch t {
	case Base64:
		return Base64Encode(rs), nil
	case Hex:
		return HexEncode(rs), nil
	default:
		return string(rs), nil
	}
}

func EasyDecrypt(easyType, cipherText, key, iv string) (string, error) {
	c, m, p, t, err := easyCheck(easyType)
	if err != nil {
		return "", err
	}
	var source []byte
	switch t {
	case Base64:
		source, err = Base64Decode(cipherText)
	case Hex:
		source, err = HexDecode(cipherText)
	default:
		source=[]byte(cipherText)
	}
	if err != nil {
		return "", err
	}

	rs, err := Decrypt(c, source, []byte(key), []byte(iv), m, p)
	if err != nil {
		return "", err
	}
	return string(rs), nil
}

func easyCheck(easyType string) (cryptoType, mode, padding, transcode, error) {
	var c cryptoType
	var m mode
	var p padding
	var t transcode
	easyTypeArr := strings.Split(easyType, "/")
	if arrLen := len(easyTypeArr); arrLen != 3 && arrLen != 4 {
		return c, m, p, t, errors.New("easyType should be one of [cryptoType/mode/padding/transcode,cryptoType/mode/padding]")
	}

	switch strings.ToUpper(easyTypeArr[0]) {
	case "AES":
		c = Aes
	case "DES":
		c = Des
	case "3DES":
		c = TriDes
	default:
		return c, m, p, t, errors.New("easyType's first value must be one of [AES,DES,3DES]")
	}

	switch strings.ToUpper(easyTypeArr[1]) {
	case "ECB":
		m = ECB
	case "CBC":
		m = CBC
	case "CFB":
		m = CFB
	case "OFB":
		m = OFB
	case "CTR":
		m = CTR
	default:
		return c, m, p, t, errors.New("easyType's second value must be one of [ECB,CBC,CFB,OFB,CTR]")
	}

	switch strings.ToUpper(easyTypeArr[2]) {
	case "NO":
		p = No
	case "ZERO":
		p = Zero
	case "PKCS5":
		p = Pkcs5
	case "PKCS7":
		p = Pkcs7
	default:
		return c, m, p, t, errors.New("easyType's third value must be one of [No,Zero,Pkcs5,Pkcs7]")
	}

	switch strings.ToUpper(easyTypeArr[3]) {
	case "BASE64":
		t = Base64
	case "HEX":
		t = Hex
	default:
		return c, m, p, t, errors.New("easyType's fourth value must be one of [Base64,Hex]")
	}
	return c, m, p, t, nil
}
