package goencryption

import (
	"reflect"
	"testing"
)
var (
	testAesKey  = []byte("12345678123456781234567812345678")
	testAesData = []byte("123abc1234567abcdefg")
	testAesIv   = []byte("<------><------>")
)
func TestAesCBC(t *testing.T) {
	dst, err := AesCBCPkcs7Encrypt(testAesData, testAesKey,testAesIv)
	if err != nil {
		t.Errorf("AesCBCPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := AesCBCPkcs7Decrypt(dst, testAesKey,testAesIv)
	if err != nil {
		t.Errorf("AesCBCPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testAesData) {
		t.Errorf("AesCBCPkcs7Decrypt() got = %v, want %v", src, testAesData)
	}
}

func TestAesCFB(t *testing.T) {
	dst, err := AesCFBPkcs7Encrypt(testAesData, testAesKey,testAesIv)
	if err != nil {
		t.Errorf("AesCFBPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := AesCFBPkcs7Decrypt(dst, testAesKey,testAesIv)
	if err != nil {
		t.Errorf("AesCFBPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testAesData) {
		t.Errorf("AesCFBPkcs7Decrypt() got = %v, want %v", src, testAesData)
	}
}

func TestAesCTR(t *testing.T) {
	dst, err := AesCTRPkcs7Encrypt(testAesData, testAesKey,testAesIv)
	if err != nil {
		t.Errorf("AesCTRPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := AesCTRPkcs7Decrypt(dst, testAesKey,testAesIv)
	if err != nil {
		t.Errorf("AesCTRPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testAesData) {
		t.Errorf("AesCTRPkcs7Decrypt() got = %v, want %v", src, testAesData)
	}
}

func TestAesECB(t *testing.T) {
	dst, err := AesECBPkcs7Encrypt(testAesData, testAesKey)
	if err != nil {
		t.Errorf("AesECBPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := AesECBPkcs7Decrypt(dst, testAesKey)
	if err != nil {
		t.Errorf("AesECBPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testAesData) {
		t.Errorf("AesECBPkcs7Decrypt() got = %v, want %v", src, testAesData)
	}
}

func TestAesOFB(t *testing.T) {
	dst, err := AesOFBPkcs7Encrypt(testAesData, testAesKey,testAesIv)
	if err != nil {
		t.Errorf("AesOFBPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := AesOFBPkcs7Decrypt(dst, testAesKey,testAesIv)
	if err != nil {
		t.Errorf("AesOFBPkcs7Encrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testAesData) {
		t.Errorf("AesOFBPkcs7Encrypt() got = %v, want %v", src, testAesData)
	}
}