package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// 检查是否提供了目录路径作为命令行参数
	if len(os.Args) < 2 {
		fmt.Println("Please provide a directory path as an argument.")
		return
	}
	directory := os.Args[1]

	// 私钥字符串表示
	privateKeyString := `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAo6siZm7gTPS95JuPQqXK+LFIggdtft2WHcmdOjSd1RQOZ5SF
db1edzSdTYVYZv6gokbcxDgyhNmB18uQityAiO75gN1XOzo9TQlbnr6bDKSmv5AG
LWQm10FDRVGeq9UA3vmjb+yY8aKP1P67SIuDMFAjt3rWLAPzbO9Y/QgT1EQvFNEb
UP82Nf4rSRY1llL+oQmrl4rpx47IKgJ31QmOfvbBtgEaqEUjvX2f223BCLcwrLhl
SUZaaWFj1pHsFSf+ozL02sQncFXHBLGxAW9Brdxn9B6vWVVCVvXTGJCOs97B2Ug1
n23QGDp2lQK1Wy9D143q6URSq473SLbDRDpbNwIDAQABAoIBAF27m9boNwM7wykS
wggcZVLqTSlS0a2vf9KNbcMw8RdgBiPiFlDo5BoHAvOro4ZQ23Q0eyjROnWFD+yj
g6NTRzWlDzVzDgs4fnUJH/SZGrkx7uGUvUTvr6LlmH4xkVq9gWMxux1Vdf4k6JTG
UkHozHg13U6uRcwtcxL3PJKlNp4AiAZbvfN2xffMnYrLnbtjD6F/j+TVgH1zHWcX
Nxzvp3A//2xKvQzPA756vw7ELtbR2xLoMvWQaao2Nkw/IKMJlCCWL+vrOrJWqRxx
sv6jvuUPSFJg3AZOcLGLmNvaId6o6XfjFdSEt8BE/6RF1dgejUrf8TAcadTHeU1K
ljR0rvkCgYEA1OjvBPRevjj0yBcr5R+tcq1/CGXI/LaQQ7s1QDSz/D2hvKbl2ldd
0GI31EXGRBybFLsz0KftqEaXLnTUrhRgE4MLEjtlgiWGOFK6dS8NivrZQrRZoEYa
CiZ4JUaZXbbwQsH+3FebwvPdjRJH19s3HwisCPlcgwfTWZwCxCyl2U0CgYEAxMr0
ztbEL4IVWT2nDxgdGWM8Ra4rqiKyT6A2j6He2SgbN4Qs3B+hdTDDTjJieOzlcTeM
9Q/7X7svUIgffqJxXrNdMuvnQmcBRSkveVCJ2YGmYcHtYUGU1hFDkixHL55Um5UO
SKJOeNjk3LvUTHcwO+8g/Kc/aMaclpGv7Y5O5JMCgYEAss/C1lVqMLZjFp0nV3Io
WNTPiLz7dQra1Jeo3Him5OTaLje5eYvAlZ+3pcbIAjJIKLwkg0xV8+r9U535dQ5V
tm1rYe+SjCB5vln0kTBoXl3ZFAWl9E6L1hSC+UN20Ncwp9CH/IRzo+LuImnE/sv0
WlMNMShEgyOSZIL7a8jXrU0CgYBh3Qg3ICh587fIJFfCstwttuLPSBkgx5Zi8KqR
bQ8UcNRwHEPux7AURkapyXac6joDvntTlzoL1ltmMftvjzrPvGTZoOTlabIBAcVB
ECMtTkM+lCEHX4Szm+w9cdWIwbUTleF/j290u2+8sY+W4yLSe02tN0LaSQKwAg06
Fq33DwKBgQCSQqwsw23dSqEIMRAEZkSCYglETwp2GwLfRMlFjBWUlLPb0jubcLJo
q5ZvSl2gLyLs5+4Ga9Ex9SVdR3YOHEKZ7wm9qxI3zo8uWl23EroAa7+tEj+jUV8C
uF3LEHhVszqilvPDwPBQSiNhAwJlFaP4kU/y6vjik8gZc0fe1QoRKQ==
-----END RSA PRIVATE KEY-----
`

	// 解码PEM格式的私钥
	block, _ := pem.Decode([]byte(privateKeyString))
	if block == nil {
		fmt.Println("Failed to decode PEM block containing private key")
		return
	}
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		fmt.Printf("Unknown PEM block type %q, want %q", got, want)
		return
	}

	// 解析私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse private key:", err)
		return
	}

	// 遍历目录下的所有文件
	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".encrypted") {
			// 读取加密文件内容
			ciphertext, err := ioutil.ReadFile(path)
			if err != nil {
				fmt.Println("Failed to read encrypted file:", path, err)
				return nil
			}

			// 使用私钥解密文件内容
			plaintext, err := decrypt(privateKey, ciphertext)
			if err != nil {
				fmt.Println("Failed to decrypt file:", path, err)
				return nil
			}

			// 将解密后的内容写入同名文件去除“.encrypted”
			decryptedFilePath := strings.TrimSuffix(path, ".encrypted")
			err = ioutil.WriteFile(decryptedFilePath, plaintext, 0644)
			if err != nil {
				fmt.Println("Failed to write decrypted file:", decryptedFilePath, err)
				return nil
			}
			fmt.Println("File decrypted:", path)

			// 删除加密文件
			err = os.Remove(path)
			if err != nil {
				fmt.Println("Failed to delete encrypted file:", path, err)
				return nil
			}
			fmt.Println("Encrypted file deleted:", path)
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error walking directory:", err)
		return
	}
}

// 使用分块解密
func decrypt(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	var plaintext []byte
	keySize := privateKey.Size()

	for i := 0; i < len(ciphertext); i += keySize {
		end := i + keySize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		chunk, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext[i:end])
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, chunk...)
	}

	return plaintext, nil
}
