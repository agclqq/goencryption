package goencryption

import (
	"fmt"
	"testing"
)

func TestEasyEncrypt(t *testing.T) {
	des := map[string]string{
		"key":  "12345678",
		"data": "12345678abcdefgh",
		"iv":   "---><---",
	}

	triDes := map[string]string{
		"key":  "123456781234567812345678",
		"data": "12345678abcdefgh",
		"iv":   "(----)->",
	}

	aes := map[string]string{
		"key":  "12345678123456781234567812345678",
		"data": "12345678abcdefgh",
		"iv":   "<------><------>",
	}

	cryptoType := []string{"aes", "des", "3des"}
	mode := []string{"ECB", "CBC", "CFB", "OFB", "CTR"}
	padding := []string{"No","Zero", "Pkcs5", "Pkcs7"}
	transcode := []string{"Base64", "Hex"}

	for _, cv := range cryptoType {
		var d map[string]string
		switch cv {
		case "aes":
			d = aes
		case "des":
			d = des
		case "3des":
			d = triDes
		}
		for _, mv := range mode {
			for _, pv := range padding {
				if cv=="aes" && pv=="Pkcs5"{
					continue // The block size of AES is 16, and the complement length needs to be 16, while the length of PKCS5 is 8
				}
				for _, tv := range transcode {
					fmt.Println(cv+"/"+mv+"/"+pv+"/"+tv)
					desSource, err := EasyEncrypt(cv+"/"+mv+"/"+pv+"/"+tv, d["data"], d["key"], d["iv"])
					if err != nil {
						t.Fatal(err,cv+"/"+mv+"/"+pv+"/"+tv, d["data"], d["key"], d["iv"])
					}
					data, err := EasyDecrypt(cv+"/"+mv+"/"+pv+"/"+tv, desSource, d["key"], d["iv"])
					if err != nil {
						t.Fatal(err)
					}
					if data != d["data"] {
						t.Fatalf("EasyEncrypt is faile,\n" +
							"cv:%s ,mv:%s,pv:%s,tv%s,data:%s,key:%s,iv:%s \n" +
							"want %x, got %x", cv,mv,pv,tv, d["data"], d["key"], d["iv"],d["data"], data)
					}
				}
			}
		}
	}
}
