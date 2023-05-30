package webauthn_gin

import (
	"github.com/everFinance/goar/utils"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	EcdsaPublic    = "ecdsa"
	WebauthnPublic = "webauthn"
	RsaPublic      = "rsa"
)

type AA struct {
	Id     string
	Name   string
	Public webauthn.Credential // key: 公钥类型，val: 公钥凭证
}

// type EverAccount struct {
// 	ID uint64
// 	Nonce int64
// 	PublicType map[string]string // key: 公钥 id, val: 公钥类型
// 	PublicVal map[string]interface{} // key: 公钥id，val：公钥
// }

func NewAA(id string, email string) *AA {
	return &AA{
		Id:   id,
		Name: email,
	}
}

func (a *AA) AddCredential(c webauthn.Credential) {
	a.Public = c
}

func (a *AA) WebAuthnID() []byte {
	id, _ := utils.Base64Decode(a.Id)
	return id
}

func (a *AA) WebAuthnName() string {
	return a.Name
}

func (a *AA) WebAuthnDisplayName() string {
	return a.Name
}

func (a *AA) WebAuthnCredentials() []webauthn.Credential {
	return []webauthn.Credential{a.Public}
}

func (a *AA) WebAuthnIcon() string {
	return ""
}
