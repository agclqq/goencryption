package goencryption

import (
	"crypto"
	"fmt"
	"testing"
)

func TestGenerateRSAKey(t *testing.T) {
	pri, pub, _ := GenKeys(512)
	fmt.Println(string(pri))
	fmt.Println(string(pub))

	pub1,err:=GenPubKeyFromPrvKey(pri)
	if err!=nil{
		t.Fatal(err)
	}

	if string(pub)!=string(pub1){
		t.Fatalf("pub is %s pub1 is %s",pub,pub1)
	}
}

func TestCrypt(t *testing.T) {
	msg:="q我是一条小金鱼，hahah12_-%^&*()_+[]aafdf"
	pri, pub, err := GenKeys(512)
	if err!=nil{
		t.Fatal(err)
	}

	mi,err:=PubKeyEncrypt(pub,[]byte(msg))
	if err!=nil{
		t.Fatal(err)
	}
	ming,err:=PrvKeyDecrypt(pri,mi)
	if err!=nil{
		t.Fatal(err)
	}
	if string(ming)!=msg{
		t.Errorf("TestCrypt,got %s,want %s",string(ming),msg)
	}
}

func TestSign(t *testing.T) {
	sign:="我是要签名的内容"
	pri, pub, err := GenKeys(512)
	if err!=nil{
		t.Fatal(err)
	}
	hash:=crypto.SHA1
	signMi,err:=PrvKeySign(pri,[]byte(sign),hash)
	if err!=nil{
		t.Fatal(err)
	}
	err=PubKeyVerifySign(pub,[]byte(sign),signMi,hash)
	if err!=nil{
		t.Fatal(err)
	}
}