package alipay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
)

const (
	SIGN_TYPE_RSA  = "RSA"
	SIGN_TYPE_RSA2 = "RSA2"
)

// RsaSign 签名
// @Param content string 待签名字符串
// @Param privateKey string 加签私钥
// @Param sign_type string 签名方式
func RsaSign(content, privateKey, signType string) (string, error) {
	hash, err := getHashType(signType)
	if err != nil {
		return "", err
	}

	h := crypto.Hash.New(hash)
	_, err = h.Write([]byte(content))
	if err != nil {
		return "", errors.New("hash content error: " + err.Error())
	}

	keyBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", errors.New("decode private key error: " + err.Error())
	}

	keyI, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return "", errors.New("parse private key error: " + err.Error())
	}

	key, ok := keyI.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("private key should be private key")
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, hash, h.Sum(nil))
	if err != nil {
		return "", errors.New("sign error: " + err.Error())
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// RsaCheckV1 此方法会去掉sign_type做验签，暂时除生活号（原服务窗）激活开发者模式外都使用V1。
// @param params map[string]string 参数列表(包括待验签参数和签名值sign) key-参数名称 value-参数值
// @param publicKey string 验签公钥
// @Param sign_type string 签名方式
func RsaCheckV1(params map[string]string, publicKey, charset, signType string) error {
	sign, ok := params["sign"]
	if !ok {
		return errors.New("sign is needed")
	}

	signByte, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return errors.New("decode sign error: " + err.Error())
	}

	content := GetContentToSign(params)

	hash, err := getHashType(signType)
	if err != nil {
		return err
	}

	h := crypto.Hash.New(hash)
	_, err = h.Write([]byte(content))
	if err != nil {
		return errors.New("hash content error: " + err.Error())
	}

	keyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return errors.New("decode private key error: " + err.Error())
	}

	keyI, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return errors.New("parse public key error: " + err.Error())
	}

	key, ok := keyI.(*rsa.PublicKey)
	if !ok {
		return errors.New("publicKey should be public key")
	}

	return rsa.VerifyPKCS1v15(key, hash, h.Sum(nil), signByte)
}

// RsaCheckV2 此方法不会去掉sign_type验签，用于生活号（原服务窗）激活开发者模式
// @param params map[string]string 参数列表(包括待验签参数和签名值sign) key-参数名称 value-参数值
// @param publicKey string 验签公钥
// @Param charset string 加签字符集
// @Param sign_type string 签名方式
func RsaCheckV2(params map[string]string, publicKey, charset, signType string) bool {
	return true
}

func GetContentToSign(params map[string]string) string {
	if len(params) < 1 {
		return ""
	}
	keys := getSortedKeys(params)
	sortedParam := []string{}
	for i := range keys {
		if val, ok := params[keys[i]]; ok {
			sortedParam = append(sortedParam, keys[i]+"="+val)
		}
	}

	return strings.Join(sortedParam, "&")
}

func getSortedKeys(params map[string]string) []string {
	keys := []string{}
	for k := range params {
		if k != "sign" {
			keys = append(keys, k)
		}
	}

	sort.Strings(keys)

	return keys
}

func getHashType(signType string) (crypto.Hash, error) {
	var (
		hash crypto.Hash
		err  error
	)

	switch strings.ToUpper(signType) {
	case SIGN_TYPE_RSA:
		hash = crypto.SHA1
	case SIGN_TYPE_RSA2:
		hash = crypto.SHA256
	default:
		err = errors.New("Bad signType " + signType)
	}

	return hash, err
}
