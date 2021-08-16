package goencryption

import (
	"reflect"
	"testing"
)

var (
	testTripleKey  = []byte("123456781234567812345678")
	testTripleData = []byte("123abc1234567abcdefg")
	testTripleIv   = []byte("(----)->")
)

func TestTripleDesECB(t *testing.T) {
	dst, err := TripleDesECBPkcs7Encrypt(testTripleData, testTripleKey)
	if err != nil {
		t.Errorf("DesCBCPkcs7Encrypt() error = %v, wantErr %v", err, false)
		return
	}
	src, err := TripleDesECBPkcs7Decrypt(dst, testTripleKey)
	if err != nil {
		t.Errorf("DesCBCPkcs7Encrypt() error = %v, wantErr %v", err, false)
		return
	}
	if !reflect.DeepEqual(src, testTripleData) {
		t.Errorf("DesCBCPkcs7Encrypt() got = %v, want %v", src, testTripleData)
	}
}

func TestTripleDesCBC(t *testing.T) {
	dst, err := TripleDesCBCPkcs7Encrypt(testTripleData, testTripleKey, testTripleIv)
	if err != nil {
		t.Errorf("TripleDesCBCPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := TripleDesCBCPkcs7Decrypt(dst, testTripleKey, testTripleIv)
	if err != nil {
		t.Errorf("TripleDesCBCPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testTripleData) {
		t.Errorf("DesCBCPkcs7Encrypt() got = %v, want %v", src, testTripleData)
	}
}

func TestTripleDesCFB(t *testing.T) {
	dst, err := TripleDesCFBPkcs7Encrypt(testTripleData, testTripleKey, testTripleIv)
	if err != nil {
		t.Errorf("TripleDesCFBPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := TripleDesCFBPkcs7Decrypt(dst, testTripleKey, testTripleIv)
	if err != nil {
		t.Errorf("TripleDesCFBPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testTripleData) {
		t.Errorf("DesCBCPkcs7Encrypt() got = %v, want %v", src, testTripleData)
	}
}

func TestTripleDesCTR(t *testing.T) {
	dst, err := TripleDesCTRPkcs7Encrypt(testTripleData, testTripleKey, testTripleIv)
	if err != nil {
		t.Errorf("TripleDesCTRPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := TripleDesCTRPkcs7Decrypt(dst, testTripleKey, testTripleIv)
	if err != nil {
		t.Errorf("TripleDesCTRPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testTripleData) {
		t.Errorf("DesCBCPkcs7Encrypt() got = %v, want %v", src, testTripleData)
	}
}

func TestTripleDesOFB(t *testing.T) {
	dst, err := TripleDesOFBPkcs7Encrypt(testTripleData, testTripleKey, testTripleIv)
	if err != nil {
		t.Errorf("TripleDesOFBPkcs7Encrypt() error = %v", err)
		return
	}
	src, err := TripleDesOFBPkcs7Decrypt(dst, testTripleKey, testTripleIv)
	if err != nil {
		t.Errorf("TripleDesOFBPkcs7Decrypt() error = %v", err)
		return
	}
	if !reflect.DeepEqual(src, testTripleData) {
		t.Errorf("DesCBCPkcs7Encrypt() got = %v, want %v", src, testTripleData)
	}
}
