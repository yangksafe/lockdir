package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
)

func main() {
    // 选择要生成的密钥的位数
    keySize := 2048

    // 使用随机数生成器生成密钥对
    privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
    if err != nil {
        fmt.Println("Failed to generate private key:", err)
        return
    }

    // 将私钥编码为ASN.1 DER格式
    privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

    // 创建一个PEM块来保存私钥
    privateKeyBlock := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    // 将私钥写入文件
    privatePemFile, err := os.Create("private.pem")
    if err != nil {
        fmt.Println("Failed to create private key file:", err)
        return
    }
    defer privatePemFile.Close()
    err = pem.Encode(privatePemFile, privateKeyBlock)
    if err != nil {
        fmt.Println("Failed to write private key to file:", err)
        return
    }
    fmt.Println("Private key generated and saved to private.pem")

    // 获取公钥
    publicKey := privateKey.PublicKey

    // 将公钥编码为ASN.1 DER格式
    publicKeyBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
    if err != nil {
        fmt.Println("Failed to marshal public key:", err)
        return
    }

    // 创建一个PEM块来保存公钥
    publicKeyBlock := &pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    // 将公钥写入文件
    publicPemFile, err := os.Create("public.pem")
    if err != nil {
        fmt.Println("Failed to create public key file:", err)
        return
    }
    defer publicPemFile.Close()
    err = pem.Encode(publicPemFile, publicKeyBlock)
    if err != nil {
        fmt.Println("Failed to write public key to file:", err)
        return
    }
    fmt.Println("Public key generated and saved to public.pem")
}
