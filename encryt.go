package alipay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
)

const (
	AES_ALG         = "AES"
	AES_CBC_PCK_ALG = "AES/CBC/PKCS5Padding"
)

var iv = iniIv(AES_CBC_PCK_ALG)

// EncryptContent 加密内容
// @Param content string
// @Param encryptType string
// @Param encryptKey string
// @Param charset string
func EncryptContent(content, encryptType, encryptKey, charset string) (string, error) {
	if strings.ToUpper(encryptType) == AES_ALG {
		return AESBase64Encrypt(content, encryptKey)
	}

	return "", errors.New("当前不支持该算法类型：encrypeType=" + encryptType)
}

// DecryptContent 解密内容
func DecryptContent(content, encryptType, encryptKey, charset string) (string, error) {
	if strings.ToUpper(encryptType) == AES_ALG {
		return AESBase64Decrypt(content, encryptKey)
	}

	return "", errors.New("当前不支持该算法类型：encrypeType=" + encryptType)
}

// AES Base64 加密
func AESBase64Encrypt(content string, aesKey string) (string, error) {
	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)
	source := PKCS5Padding([]byte(content), block.BlockSize())
	dst := make([]byte, len(source))
	blockMode.CryptBlocks(dst, source)

	return base64.RawStdEncoding.EncodeToString(dst), nil
}

// AESBase64Decrypt AES Base64 解密
func AESBase64Decrypt(content string, aesKey string) (string, error) {
	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)

	source, err := base64.RawStdEncoding.DecodeString(content)
	if err != nil {
		return "", err
	}

	dst := make([]byte, len(source))
	blockMode.CryptBlocks(dst, source)

	return string(PKCS5Unpadding(dst)), nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Unpadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func iniIv(fullAlg string) []byte {
	blockSize := 16
	if b, e := aes.NewCipher([]byte(fullAlg)); e == nil {
		blockSize = b.BlockSize()
	}

	iv := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		iv[i] = 0
	}

	return iv
}
