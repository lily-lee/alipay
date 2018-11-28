package alipay

import (
	"fmt"
	"testing"
)

var aesKey = "this is a aesKey"
var content = "this is content"

func TestEncryptContent(t *testing.T) {
	s, e := EncryptContent(content, "AES", aesKey, "UTF-8")
	fmt.Println("s: ", s)
	fmt.Println("e: ", e)
	c, e := DecryptContent(s, "AES", aesKey, "UTF-8")
	fmt.Println("c: ", c)
	fmt.Println("e: ", e)
	if c != content {
		t.Error("not equal.")
	}
}
