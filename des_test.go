package goencryption

import (
	"reflect"
	"testing"
)

var (
	testKey     = []byte("12345678")
	testData = []byte("123abc1234567abcdefg")
	testIv      = []byte("---><---")
)

func TestDesECB(t *testing.T) {
	dst, err := DesECBPkcs7Encrypt(testAesData, testKey)
	if err != nil {
		t.Errorf("DesECBPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := DesECBPkcs7Decrypt(dst, testKey)
	if err != nil {
		t.Errorf("DesECBPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testAesData) {
		t.Errorf("DesCBCPkcs7Encrypt() got = %v, want %v", src, testAesData)
	}
}

func TestDesCBC(t *testing.T) {
	dst, err := DesCBCPkcs7Encrypt(testAesData, testKey, testIv)
	if err != nil {
		t.Errorf("DesCBCPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := DescCBCPkcs7Decrypt(dst, testKey, testIv)
	if err != nil {
		t.Errorf("DescCBCPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testAesData) {
		t.Errorf("DesCBCPkcs7Encrypt() got = %v, want %v", src, testAesData)
	}
}

func TestDesCFB(t *testing.T) {
	dst, err := DesCFBPkcs7Encrypt(testAesData, testKey, testIv)
	if err != nil {
		t.Errorf("DesCFBPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := DesCFBPkcs7Decrypt(dst, testKey, testIv)
	if err != nil {
		t.Errorf("DesCFBPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testAesData) {
		t.Errorf("DesCBCPkcs7Encrypt() got = %v, want %v", src, testAesData)
	}
}

func TestDesOFB(t *testing.T) {
	dst, err := DesOFBPkcs7Encrypt(testAesData, testKey, testIv)
	if err != nil {
		t.Errorf("DesOFBPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := DesOFBPkcs7Decrypt(dst, testKey, testIv)
	if err != nil {
		t.Errorf("DesOFBPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testAesData) {
		t.Errorf("DesCBCPkcs7Encrypt() got = %v, want %v", src, testAesData)
	}
}

func TestDesCTR(t *testing.T) {
	dst, err := DesCTRPkcs7Encrypt(testAesData, testKey, testIv)
	if err != nil {
		t.Errorf("DesCTRPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := DesCTRPkcs7Decrypt(dst, testKey, testIv)
	if err != nil {
		t.Errorf("DesCTRPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testAesData) {
		t.Errorf("DesCBCPkcs7Encrypt() got = %v, want %v", src, testAesData)
	}
}
