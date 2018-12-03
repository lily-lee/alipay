package alipay

import (
	"testing"
)

var aesKey = "this is a aesKey"
var content = "this is content"
var encryptedContent = "nDmr0Y8WkS9mAcsDR0VZhA"

func TestEncryptContent(t *testing.T) {
	s, e := EncryptContent(content, "AES", aesKey, "UTF-8")
	if e != nil {
		t.Error("test EncryptContent error: ", e)
	}

	if s != encryptedContent {
		t.Error("test EncryptContent failed.")
	}

}

func TestDecryptContent(t *testing.T) {
	c, e := DecryptContent(encryptedContent, "AES", aesKey, "UTF-8")
	if e != nil {
		t.Error("test DecryptContent error: ", e)
	}

	if c != content {
		t.Error("test DecryptContent failed. not equal.")
	}
}
