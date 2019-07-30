package serviceprovider

import (
	"bytes"
	"encoding/xml"
	"unicode"
)

type EncryptBody struct {
	XMLName            struct{} `xml:"xml"`
	ToUserName         string   `xml:"ToUserName"`
	Base64EncryptedMsg []byte   `xml:"Encrypt"`
}

var (
	msgStartElementLiteral = []byte("<xml>")
	msgEndElementLiteral   = []byte("</xml>")

	msgToUserNameStartElementLiteral = []byte("<ToUserName>")
	msgToUserNameEndElementLiteral   = []byte("</ToUserName>")

	msgEncryptStartElementLiteral = []byte("<Encrypt>")
	msgEncryptEndElementLiteral   = []byte("</Encrypt>")

	cdataStartLiteral = []byte("<![CDATA[")
	cdataEndLiteral   = []byte("]]>")
)

func XmlUnmarshal(data []byte, p *EncryptBody) error {
	data = bytes.TrimSpace(data)
	if !bytes.HasPrefix(data, msgStartElementLiteral) || !bytes.HasSuffix(data, msgEndElementLiteral) {
		return xml.Unmarshal(data, p)
	}
	data2 := data[len(msgStartElementLiteral) : len(data)-len(msgEndElementLiteral)]

	// ToUserName
	ToUserNameElementBytes := data2
	i := bytes.Index(ToUserNameElementBytes, msgToUserNameStartElementLiteral)
	if i == -1 {
		return xml.Unmarshal(data, p)
	}
	ToUserNameElementBytes = ToUserNameElementBytes[i+len(msgToUserNameStartElementLiteral):]
	ToUserNameElementBytes = bytes.TrimLeftFunc(ToUserNameElementBytes, unicode.IsSpace)
	if !bytes.HasPrefix(ToUserNameElementBytes, cdataStartLiteral) {
		return xml.Unmarshal(data, p)
	}
	ToUserNameElementBytes = ToUserNameElementBytes[len(cdataStartLiteral):]
	i = bytes.Index(ToUserNameElementBytes, cdataEndLiteral)
	if i == -1 {
		return xml.Unmarshal(data, p)
	}
	ToUserName := ToUserNameElementBytes[:i]
	ToUserNameElementBytes = ToUserNameElementBytes[i+len(cdataEndLiteral):]
	ToUserNameElementBytes = bytes.TrimLeftFunc(ToUserNameElementBytes, unicode.IsSpace)
	if !bytes.HasPrefix(ToUserNameElementBytes, msgToUserNameEndElementLiteral) {
		return xml.Unmarshal(data, p)
	}
	ToUserNameElementBytes = ToUserNameElementBytes[len(msgToUserNameEndElementLiteral):]

	// Encrypt
	EncryptElementBytes := ToUserNameElementBytes
	i = bytes.Index(EncryptElementBytes, msgEncryptStartElementLiteral)
	if i == -1 {
		EncryptElementBytes = data2
		i = bytes.Index(EncryptElementBytes, msgEncryptStartElementLiteral)
		if i == -1 {
			return xml.Unmarshal(data, p)
		}
	}
	EncryptElementBytes = EncryptElementBytes[i+len(msgEncryptStartElementLiteral):]
	EncryptElementBytes = bytes.TrimLeftFunc(EncryptElementBytes, unicode.IsSpace)
	if !bytes.HasPrefix(EncryptElementBytes, cdataStartLiteral) {
		return xml.Unmarshal(data, p)
	}
	EncryptElementBytes = EncryptElementBytes[len(cdataStartLiteral):]
	i = bytes.Index(EncryptElementBytes, cdataEndLiteral)
	if i == -1 {
		return xml.Unmarshal(data, p)
	}
	Encrypt := EncryptElementBytes[:i]
	EncryptElementBytes = EncryptElementBytes[i+len(cdataEndLiteral):]
	EncryptElementBytes = bytes.TrimLeftFunc(EncryptElementBytes, unicode.IsSpace)
	if !bytes.HasPrefix(EncryptElementBytes, msgEncryptEndElementLiteral) {
		return xml.Unmarshal(data, p)
	}

	p.ToUserName = string(ToUserName)
	p.Base64EncryptedMsg = Encrypt
	return nil
}
