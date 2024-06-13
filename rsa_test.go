package goencryption

import (
	"crypto"
	"fmt"
	"testing"
)

var (
	// openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
	// openssl rsa -pubout -in private_key.pem -out public_key.pem
	opensslRsaKeys = map[string][]byte{
		"private": []byte("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFB7llOT2iKEWg\n+S1olpc+E1JDlttfZ4yeKLztmM3hbsDK97nwK9kiqFJVkO1ZDxwNrgBNxg4V1cvF\nTsEkPFPYZGiXzpdMuootTdjwop4ihYtjnw+lKFZWM5rgV9szGE22LoFWpgNmJcS/\nHqQh+ART1ceA68uVWiRS/mBlcCB2ADToFEhMzo6lRWOIkX+ppz357HN0Y2Bxo9Aj\njwjS2iT39LG3FWhgEgn/oivHl+D/iRk2q2dy/IvdGimrGkE1eT8mnyKu50InYgku\nEZpFBRKl0M7o2TmKdRZT8dN1ZQ+/d9RYRbjJ3tKiRYpUhjVYVV+fMU3x9QMZYYza\n1n6LmtjTAgMBAAECggEAB6ccptdZ0v4QckerYVgUCMe0Vsa5v5NkjVIUwH/CY2Kr\nX1bO5Iq3dNan2AX4ihCBrPBYt6ydKHD06LV93/vt38ZKn7bY/pRyQH85EWOnk7yv\nJM/tSiNucwuvFM6kx2/GuPBGesiY8jM+WJQGmQEqndz8UkAWWLc3GPgjY10/DYY0\nEJU0lXnnXiqh5di/vwOrddtTw/AExRwaxUMWqmFJD/wvfJes4neigHmx+ljbczOE\nb1VJZA0fAtzpazKhTgP4mlKIRdsk/6eO+4oAs1Pzl1MQ7swH463Y7k6XbX41fxPT\nuRVh8axuudcrkILcxrUsMZRU90RqzcYYHiXhLjo97QKBgQDrbojO+zi6X9FIC1zr\npiCN6TprJ1IdM/O0Sk+9pbEaP0NfzQlRiDK7kvQo6wftKwlcV4e8s0JcSnbAsSzg\nUqdylO86sC63KlnxAAAdoUyGJQ+shFol9MFjVnxCSp/Efp600q/xX83gkV9nwF7u\n13+GXp8bf71djy8jW5qhJ9D/TwKBgQDWPlUZaEPUkOF4auMOocfo4meMX2SQUI6u\ncTjdTqeqMpvAKTBL7f7jaEj+YciLFLdJ74KIK1XpYHY52S/az+J7VGBYmAwuYkyr\nTbLtZSa7I7YyWLvAZH/lDufkIOavI/O+bkrm7+/RZ1lY3jr1SUaY3MDOeFBHcA8f\ngPGcgvkNPQKBgQCp6EbBodqJ3tbJuLGhu23pHLW1WVZQjwrFRZAQ3QBYYem8vNuJ\nxNJgPqkI0r4Qsqt5wg3K6E/vDSpw3Cz3447HCacw4q+ELwNkA00SFTOF6D9MkOQC\nWoYqq+LXcMWm6H6fHyIs/6gz9pY06UdZ9ZoqHiWTkffXCpvJV7XbskGJzwKBgDWL\nMIOADmvCpccNl5+hiS/H3a80bBKxP2eTfm246ahcq5ZT9PEVEv3Mo2mIELHJxKEi\nzdGwWvFPnVyJzi72g5jlFostvOWexaCOc6hm/k4I99EPYiUMOPaLSiM2odClwJYY\nRHoA/0Ore6X9LGj/Hji3+yve39lqxSzPchL2nL3VAoGBAJygnlYRyGey0uVVN//l\nbBkHwX/YM2UtXMcdDcnVbn6OL1vFrvUptA/W32thMYGgfQOrmmb37YSTlEhA9DOK\nzTyCRF+axHFpmjstzIdAk4Yj48njJxCLywG7J2rEBNgtWiiyXFXH6pijvMjKM5VD\nBwW3PKsgMRGkGi0oXbQwnNC6\n-----END PRIVATE KEY-----"),
		"public":  []byte("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxQe5ZTk9oihFoPktaJaX\nPhNSQ5bbX2eMnii87ZjN4W7Ayve58CvZIqhSVZDtWQ8cDa4ATcYOFdXLxU7BJDxT\n2GRol86XTLqKLU3Y8KKeIoWLY58PpShWVjOa4FfbMxhNti6BVqYDZiXEvx6kIfgE\nU9XHgOvLlVokUv5gZXAgdgA06BRITM6OpUVjiJF/qac9+exzdGNgcaPQI48I0tok\n9/SxtxVoYBIJ/6Irx5fg/4kZNqtncvyL3RopqxpBNXk/Jp8irudCJ2IJLhGaRQUS\npdDO6Nk5inUWU/HTdWUPv3fUWEW4yd7SokWKVIY1WFVfnzFN8fUDGWGM2tZ+i5rY\n0wIDAQAB\n-----END PUBLIC KEY-----"),
	}
	// ssh-keygen -t rsa -b 2048 -C "<comment>"
	sshkeygenRsaKeys = map[string][]byte{
		"private": []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAyYNurEJTbGYFGzWG4MEXNxFYsDFD2EHB8/5TUOcdyIBsO+n0p+ye\nWCThyyyfYoH520MYAqjfokayujs66zgeIXbzRe/c1tMTQlDwdUCg/tREV/jcZBVMePw+Ou\nVjQcBoYEP913+7gFmpd4nQXXVut+x4cnH0I8Tajh9ojCrlfzdzP1/EwWquUYnDALhlJnwY\nxy3VlxPzpMhcgnpcJDo8fpvMTIbUpmGdkJoQrFcK6d7C6d5QQotjKE00T2JNZsjnwT+y3v\nefanHq8Ee/XERLyzSRU8IclPdsVnCKMNnXUmJ35XJ2hSM9LVKqpC31u6TPQkJZyJrrditL\ndHxtU7yx2wAAA8CRK2vGkStrxgAAAAdzc2gtcnNhAAABAQDJg26sQlNsZgUbNYbgwRc3EV\niwMUPYQcHz/lNQ5x3IgGw76fSn7J5YJOHLLJ9igfnbQxgCqN+iRrK6OzrrOB4hdvNF79zW\n0xNCUPB1QKD+1ERX+NxkFUx4/D465WNBwGhgQ/3Xf7uAWal3idBddW637HhycfQjxNqOH2\niMKuV/N3M/X8TBaq5RicMAuGUmfBjHLdWXE/OkyFyCelwkOjx+m8xMhtSmYZ2QmhCsVwrp\n3sLp3lBCi2MoTTRPYk1myOfBP7Le959qcerwR79cREvLNJFTwhyU92xWcIow2ddSYnflcn\naFIz0tUqqkLfW7pM9CQlnImut2K0t0fG1TvLHbAAAAAwEAAQAAAQBP47l2tXzZVsDjfp8Q\nb7zCajAc+gsJq1g3YTaqtlXKbY97WU9TW62TCFwz7mbp6Nmjob/dHhI7BYhJ6L19D2xym/\nPqYCPPTzMtcWVDNvIc1Q6bSeAmFYOR237YXqSxJpS6xXnXe55cTi+vYoWm562TYT6HMMI3\nhA2Zlr4eA8ukWSVFF4vafAQLgH4Cgi9SUTA6iibKdBzDsbUq44AQmgJ3OJPhpoEDx9+1GN\n0fhm/N90kg5kgVFnrQ2hIvjFYRzzaKF2OJrCjrqQCVuiEo5j+rUAmLmwHSs9nsqrLTYTid\nIurK0NXxG0Hh2R27q+aSgXdQl+UbgapVc2t75I81VIpBAAAAgDh+Y6sNqdCeGTtUbOjyy4\nTaUt6+2QL5VR7OiqV0mLv2v6H1QOZj7C+S7LpK3MBsoDSiASw186getoEk+98oo45BxiC0\nb/0e8MIkwW7Rho7lCN55qA2vAUNKvHUZ8PZkEhH7BaIl6CjJwN8BiQfauosTjQyZKC3V1S\nfXIQ9ju/U6AAAAgQDokcQMoG8pr/PSglH/ptTc9UMj1Y0x7Ds/2gkFQDShT3o2TkGui+d+\nKNtlTdTfX58ns/nMurY+Ixre/obHXgpGrhxlLqVHU5+UoC4iRfdb0WVdOw3sZDeDV9jNoG\nbWyCssitidMYZs+3hTA7TJFcDRJOH+slKSpeWVSjbe+CxGSwAAAIEA3dCyUAqtOJxCgl32\nSn8dvWiz9TQWf+ep2rxW01UxQ5lG4N+krT54lzU2jujydhBgSaVQ3fyz+v584+568s8/76\ns/tBIG2EIn4NaqOhMD9e5sGATfzZq7QNu1AUIoMslbxVERJCueC4S57h0Jy0HX1fkgDujk\nZmFFaCLmuF8xSLEAAAAJPGNvbW1lbnQ+AQI=\n-----END OPENSSH PRIVATE KEY-----"),
		"public":  []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJg26sQlNsZgUbNYbgwRc3EViwMUPYQcHz/lNQ5x3IgGw76fSn7J5YJOHLLJ9igfnbQxgCqN+iRrK6OzrrOB4hdvNF79zW0xNCUPB1QKD+1ERX+NxkFUx4/D465WNBwGhgQ/3Xf7uAWal3idBddW637HhycfQjxNqOH2iMKuV/N3M/X8TBaq5RicMAuGUmfBjHLdWXE/OkyFyCelwkOjx+m8xMhtSmYZ2QmhCsVwrp3sLp3lBCi2MoTTRPYk1myOfBP7Le959qcerwR79cREvLNJFTwhyU92xWcIow2ddSYnflcnaFIz0tUqqkLfW7pM9CQlnImut2K0t0fG1TvLHb <comment>"),
	}
)

func TestGenerateRSAKey(t *testing.T) {
	pri, pub, _ := GenKeys(512)
	fmt.Println(string(pri))
	fmt.Println(string(pub))

	pub1, err := GenPubKeyFromPrvKey(pri)
	if err != nil {
		t.Fatal(err)
	}

	if string(pub) != string(pub1) {
		t.Fatalf("pub is %s pub1 is %s", pub, pub1)
	}
}

func TestCrypt(t *testing.T) {
	type args struct {
		keys      [][]byte
		plainText []byte
	}
	tests := []struct {
		name string
		args args

		wantErr bool
	}{
		{name: "t1-pkcs#8", args: args{keys: func() [][]byte {
			prv, pub, err := GenKeys(512)
			if err != nil {
				t.Fatal(err)
			}
			return [][]byte{prv, pub}
		}(), plainText: []byte("q我是一条小金鱼，hahah12_-%^&*()_+[]aafdf")}, wantErr: false},
		{name: "t2-pkcs#1", args: args{keys: func() [][]byte {
			prv, err := GenPKCS1PrvKey(2048)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := GenPubKeyFromPrvKey(prv)
			if err != nil {
				t.Fatal(err)
			}
			return [][]byte{prv, pub}
		}(), plainText: []byte("q我是一条小金鱼，hahah12_-%^&*()_+[]aafdf")}, wantErr: false},
		{name: "t3", args: args{keys: [][]byte{[]byte("123"), []byte("123")}, plainText: []byte("q我是一条小金鱼，hahah12_-%^&*()_+[]aafdf")}, wantErr: true},
		{name: "t4-pkcs#8", args: args{keys: func() [][]byte {
			prv, err := GenPrvKey(2048)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := GenPubKeyFromPrvKey(prv)
			if err != nil {
				t.Fatal(err)
			}
			return [][]byte{prv, pub}
		}(), plainText: []byte("q我是一条小金鱼，hahah12_-%^&*()_+[]aafdf")}, wantErr: false},
		{name: "t5_openssl_prv-pub", args: args{keys: [][]byte{opensslRsaKeys["private"], opensslRsaKeys["public"]}, plainText: []byte("q我是一条小金鱼，hahah12_-%^&*()_+[]aafdf")}, wantErr: false},
		{name: "t6_ssh-keygen_prv-pub", args: args{keys: [][]byte{sshkeygenRsaKeys["private"], sshkeygenRsaKeys["public"]}, plainText: []byte("q我是一条小金鱼，hahah12_-%^&*()_+[]aafdf")}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypt, err := PubKeyEncrypt(tt.args.keys[1], tt.args.plainText)
			if (err != nil) != tt.wantErr {
				t.Fatal(err)
				return
			}
			decrypt, err := PrvKeyDecrypt(tt.args.keys[0], encrypt)
			if (err != nil) != tt.wantErr {
				t.Fatal(err)
				return
			}
			if (string(tt.args.plainText) != string(decrypt)) != tt.wantErr {
				t.Fatalf("TestCrypt,got %s,want %s", string(decrypt), string(tt.args.plainText))
			}
		})
	}
}

func TestSign(t *testing.T) {
	sign := "我是要签名的内容"
	pri, pub, err := GenKeys(512)
	if err != nil {
		t.Fatal(err)
	}
	hash := crypto.SHA1
	signMi, err := PrvKeySign(pri, []byte(sign), hash)
	if err != nil {
		t.Fatal(err)
	}
	err = PubKeyVerifySign(pub, []byte(sign), signMi, hash)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenPubKeyFromPrvKey(t *testing.T) {
	type args struct {
		prvKey []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "t1-pkcs#8", args: args{prvKey: func() []byte {
			pri, _, _ := GenKeys(512)
			return pri
		}()}, wantErr: false},
		{name: "t2-pkcs#1", args: args{prvKey: func() []byte {
			prvKey, err := GenPKCS1PrvKey(2048)
			if err != nil {
				t.Errorf("GenPKCS1PrvKey() error = %v", err)
				return nil
			}
			return prvKey
		}()}, wantErr: false},
		{name: "t3", args: args{prvKey: []byte("123")}, wantErr: true},
		{name: "t4-pkcs#8", args: args{prvKey: func() []byte {
			prvKey, err := GenPrvKey(2048)
			if err != nil {
				t.Errorf("GenPrvKey() error = %v", err)
				return nil
			}
			return prvKey
		}()}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenPubKeyFromPrvKey(tt.args.prvKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenPubKeyFromPrvKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	type args struct {
		prvKey    []byte
		pubKey    []byte
		plainText []byte
		hash      crypto.Hash
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "t1", args: args{prvKey: opensslRsaKeys["private"], pubKey: opensslRsaKeys["public"], plainText: []byte("q我是一条小金鱼，hahah12_-%^&*()_+[]aafdf"), hash: crypto.SHA1}, wantErr: false},
		{name: "t1", args: args{prvKey: sshkeygenRsaKeys["private"], pubKey: sshkeygenRsaKeys["public"], plainText: []byte("q我是一条小金鱼，hahah12_-%^&*()_+[]aafdf"), hash: crypto.SHA1}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sign, err := PrvKeySign(tt.args.prvKey, tt.args.plainText, tt.args.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrvKeySign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err := PubKeyVerifySign(tt.args.pubKey, tt.args.plainText, sign, tt.args.hash); (err != nil) != tt.wantErr {
				t.Errorf("PubKeyVerifySign() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
