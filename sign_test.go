package alipay

import (
	"testing"
)

var param = map[string]string{
	"time":    "2018-12-03 20:38:51",
	"name":    "test",
	"version": "1.0",
}

var sign = "kTNzyiuR1hGNOY33N/PZlWzXXWOT+wicP46N7ktHFI2VF6WD2pANKaNkogcOZ1vS51NcVkDbZRps1PZ8eHxasycLw0vpg5oxCSLDJ0/t+uwaZALLwccMAsg3hqkhbwkjlHSitL9n0ZonA85/vQybG0kwc16h2MOTFOwJsrkCanKQpOvbJCGeXQ0yOvKzaOcmKk8i7dOSKFSm63CjxNGAooz3waMdVPfYJ3RU5UL4P8NyXxAjjIWYQuntnsZArhb5i934dHnT9FODOp1/zL8jv7PpGq1xOfkL/ec0jww1637AlOUbg2ht1egCmrfHvvm6w0ngtjfr5+N5pCfNBwJlZA=="

func TestRsaSignFromStrKey(t *testing.T) {
	privateKey := "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCtjMJcoL5C3oCIs5GPCaH2wF0udsn+S0VXXtevA66XbVWsygtCfG7YUDxN8o8rxmOS5FX/+kGqylbvgiHfovHdX/M720Dngq36lCPTp41+JiPM2c6QGYfcMaCDjNgFthtWY9fBWyU16y7RRsw3WzdS6J/4DnAysbN0SVGAn2mUx0vCmfCoeeXteryDGy8E4zzT/v7bvR1FCRSRGpQ84ESQCth3ltKjdMea2dRoejwixElrNKqjAuag1xClVLBo/WKIVmGmUhXb/zf4+v2kJXqDausmp2SNCzECzrZld6ezfwoMn+KDNdTJ80qw74gQPnodJuqD6+9hnd/x4E6ZVB0jAgMBAAECggEARBCLfdaRKBqpoHOEp+uoOOUy5nEyQWh19pE81+gCxmLcEhtflSDGPFIjhJKX8hwpm0ewLueQb5JRzDdmX5ZBc4gZFiWka+fFohwNfQoepRYCPmpB6CQLM6HHCTDo3DyStiwMR0oe6umk//DbUO6WYQ7ZBmlrOYaWEgpbS625s95cd7xuyIK1mL/DwejGyYI7LXT/gJZD4cjUHWULOC1T7SPDfLHuPuV6uX8aWKTy/cff4ymABGDAmwJahXlpCYxoknsNHQgD1FxkGVXahIrlcOolpa2E5ZBp19n42494dzUcJ1W5dCGW08roqxZyQhUb+o1VCqS267WPPu1Y5po6wQKBgQDahXvaACMDZ/7hmvwVGORlOCqewhGx9F6VyDwscnhbIPHA8mJoSTALcDp7sRJjlxgQwXLo0h/qLmFiC7n7ATmbVTpXuuE81h4al1GgZWxVQT8kviqvFFMyQGhRu5HdwjkWH67Su2KrVyt9A4jLPZVaMauptIFs0/LGCLD7z2zHoQKBgQDLULrIabdnymcks/xk2PjKKnlSeCHCJS8QGQZRlngqWR6aepVTfIDlkfVaIh0FRLMbYWyMUomOXMb/4ntW9zkdZNpoKOHf135oRd0oRjBlWj0ABy/cwK+ifOvefPmeaSzSAfA6JD4aIE4RkHJY8IHDL7QwKtxOdXDn4ySrARceQwKBgEaQckUcZDIWZAUgUiTR6/cPoxuvGZ24hs6hYWUM9fafddHTs5lvgNdAv3Hv5TtJsFjAz0WFjQ7HOWU62izG4X5akEOCMne9wOzfTlmYRtpk/mn0Cr6Mtqz0hXtXMaxFqr+NLZwZLKydsoplGMhgs5jzjzZ29pBZBP2UEurNuZfhAoGARxk2GDuP3YXUR+uBCasuZVQxFPvZolDqglCd+w4Je5WqtA7GBWn2kVFXYWuohl0d3SdWlEOQwu4C0RzcUO8nU/Yewmn5gxOSqtgznI/fALJrvoTE4gen48SXnzhI+nKBL/dpkIt4BB7j7hR7SEriteUKuAVlATLkhtLR0dMRyI0CgYBOUKG9yi0GAoR1pU6DlZVOTY8a8jTTPkDEpBUf221vp6lDlesoUCjP7XZHVMRJz/oIx+iWZLIBaOv0GoGnmRkFeReI3NWZ4M89op+pEIML728uMo1iMAoqwUl8x0gs1R43kUKZjjGWUwB9Sq6GulXPJ7GLNmVN6d+z4K+WgkjosA=="

	s, err := RsaSignFromStrKey(GetContentToSign(param), "RSA2", privateKey)
	if err != nil {
		t.Error("test RsaSignFromStrKey error: ", err)
	}

	if s != sign {
		t.Error("test RsaSignFromStrKey faild!!!!!!!")
	}
}

func TestRsaCheckFromStrKey(t *testing.T) {
	pubKey := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYzCXKC+Qt6AiLORjwmh9sBdLnbJ/ktFV17XrwOul21VrMoLQnxu2FA8TfKPK8ZjkuRV//pBqspW74Ih36Lx3V/zO9tA54Kt+pQj06eNfiYjzNnOkBmH3DGgg4zYBbYbVmPXwVslNesu0UbMN1s3Uuif+A5wMrGzdElRgJ9plMdLwpnwqHnl7Xq8gxsvBOM80/7+270dRQkUkRqUPOBEkArYd5bSo3THmtnUaHo8IsRJazSqowLmoNcQpVSwaP1iiFZhplIV2/83+Pr9pCV6g2rrJqdkjQsxAs62ZXens38KDJ/igzXUyfNKsO+IED56HSbqg+vvYZ3f8eBOmVQdIwIDAQAB"
	param["sign"] = sign
	err := RsaCheckFromStrKey(param, "RSA2", pubKey)
	if err != nil {
		t.Error("test RsaCheckFromStrKey failed: ", err)
	}
}

func TestRsaSign(t *testing.T) {
	privateKey, err := ReadKeyFromPemFile("./private.pem")
	if err != nil {
		t.Error("ReadKeyFromPemFile error: ", err)
		return
	}

	s, err := RsaSign(GetContentToSign(param), "RSA2", privateKey)
	if err != nil {
		t.Error("test RsaSign error: ", err)
	}

	if s != sign {
		t.Error("test RsaSign failed.")
	}
}

func TestRsaCheck(t *testing.T) {
	pubKey, err := ReadKeyFromPemFile("./pub.pem")
	if err != nil {
		t.Error("publickey: ReadKeyFromPemFile error: ", err)
		return
	}

	err = RsaCheck(param, "RSA2", pubKey)
	if err != nil {
		t.Error("test RsaCheck error: ", err)
	}
}
