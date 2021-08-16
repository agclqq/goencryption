# goencryption
[中文说明](README_ZH.md)

## install
```go
go get github.com/agclqq/goencryption
```
## summary
Supports symmetric encryption and asymmetric encryption algorithms.

#### symmetric encryption
 * aes
 * des
 * 3des
  
#### asymmetric encryption
 * rsa

## usage

### symmetric encryption 
generic methods
```go
EasyEncrypt(easyType, plaintext, key, iv)
EasyDecrypt(easyType, ciphertext, key, iv)
```
The parameter easyType should have a format like this:`cryptoType/mode/padding`  or `cryptoType/mode/padding/transcode` 

For example:
```go
EasyEncrypt("des/CFB/Pkcs7/Base64", plaintext, key, iv)
EasyDecrypt("des/CFB/Pkcs7/Base64", ciphertext, key, iv)

EasyEncrypt("aes/CTR/Pkcs7", plaintext, key, iv)
EasyDecrypt("aes/CTR/Pkcs7", ciphertext, key, iv)

EasyEncrypt("3des/ECB/Pkcs5/Hex", plaintext, key, iv)
EasyDecrypt("3des/ECB/Pkcs5/Hex", ciphertext, key, iv)
```
The core approach to implementation is Encrypt() and Decrypt(). All other methods are facade.

#### about padding
* noPadding: The data must be must be an integer multiple of the block
* zeorPadding: It's going to fill in with zeros. If the original data ends in 0, there is a problem.
* pkcs5Padding: The complement length is 8, which can be problematic in some cases
* pkcs7Padding: Pkcs5Padding superset.Complement length is dynamic.
### asymmetric encryption

Generate both private and public keys
```go
GenKeys(bits)
```

Only the private key is generated
```go
GenPrvKey(bits)
```

Generate a public key from a private key
```go
GenPubKeyFromPrvKey(prvKey)
```

Public key encryption private key decryption
```go
PubKeyEncrypt(pubKey, plainText)
PrvKeyDecrypt(prvKey, cipherText)
```

Private key signature, public key verification signature
```go
PrvKeySign(prvKey, plainText, hash)
PubKeyVerifySign(pubKey, plainText, sign, hash)
```