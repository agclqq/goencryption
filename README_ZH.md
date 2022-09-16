# goencryption

##安装
```go
go get github.com/agclqq/goencryption
```
## 简介
支持对称和非对称加密。

#### 对称加密
 * aes
 * des
 * 3des
  
#### 非对称加密
 * rsa

## 用法

### 对称加密
通用方法
```go
EasyEncrypt(easyType, plaintext, key, iv)
EasyDecrypt(easyType, ciphertext, key, iv)
```
参数 easyType 应该为以下格式:cryptoType/mode/padding 或 cryptoType/mode/padding/transcode

**注意：** aes和pkcs5不要一起使用。The block size of AES is 16, and the complement length needs to be 16, while the length of PKCS5 is 8
For example:
```go
EasyEncrypt("des/CFB/Pkcs7/Base64", plaintext, key, iv)
EasyDecrypt("des/CFB/Pkcs7/Base64", ciphertext, key, iv)

EasyEncrypt("aes/CTR/Pkcs7/Hex", plaintext, key, iv)
EasyDecrypt("aes/CTR/Pkcs7/Hex", ciphertext, key, iv)

EasyEncrypt("3des/ECB/Pkcs5/Hex", plaintext, key, iv)
EasyDecrypt("3des/ECB/Pkcs5/Hex", ciphertext, key, iv)
```
核心方法是 Encrypt() 和 Decrypt(). 其他方法都是基于这两个方法的门面.
#### 关于补码
* noPadding: 要求原始数据长度必须是当前算法的block的正整数倍。
* zeorPadding: 会用0填充，当原始数据也是以0结尾时，会有问题。
* pkcs5Padding: 补码长度固定为8，在某些算法中，和block不匹配，会有异常
* pkcs7Padding: Pkcs5Padding的超集，补码的位置是动态的，适用各种算法，推荐。
### 非对称加密RSA

生成私钥和公钥
```go
GenKeys(bits)
```

只生成私钥
```go
GenPrvKey(bits)
```

从私钥生成公钥
```go
GenPubKeyFromPrvKey(prvKey)
```

公钥加密私钥解密
```go
PubKeyEncrypt(pubKey, plainText)
PrvKeyDecrypt(prvKey, cipherText)
```

私钥签名，公钥验证签名
```go
PrvKeySign(prvKey, plainText, hash)
PubKeyVerifySign(pubKey, plainText, sign, hash)
```
