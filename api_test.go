package webauthn_gin

import (
	"encoding/json"
	paySchema "github.com/everFinance/everpay/pay/schema"
	"github.com/everFinance/goar/utils"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

type AA struct {
	Id       string
	RawId    string `json:"rawId"`
	Type     string
	Response struct {
		AttestationObject string `json:"attestationObject"`
		ClientDataJSON    string `json:"clientDataJSON"`
	} `json:"response"`
}

func decodeBase64(s string) (protocol.URLEncodedBase64, error) {
	bs := &protocol.URLEncodedBase64{}
	err := bs.UnmarshalJSON([]byte(s))
	if err != nil {
		return nil, err
	}
	return *bs, nil
}

func TestNewServer(t *testing.T) {
	ss := `{
    "id": "tyE273KHTEpCilALINtyxOTHREojRzBzPWL-xgQgsf8",
    "rawId": "tyE273KHTEpCilALINtyxOTHREojRzBzPWL-xgQgsf8: ",
    "type": "public-key",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAILchNu9yh0xKQopQCyDbcsTkx0RKI0cwcz1i_sYEILH_pQECAyYgASFYIKcPAK4gDlSYcX0FL7WGFb8AhmFVMjTLu9NHXp8N3sorIlggcPltSo7IUg6C3DCTUd3DXLnjHag1e9r5_ul8xqQskfU=",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiU1pFNDRiYWs5cF9HMWZrRVk1RDZDbTRtVUJrNk5BbHFuMENlOVVMVkdqMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0="
    }
}`
	rr := strings.NewReader(ss)

	aa := AA{}
	err := json.NewDecoder(rr).Decode(&aa)
	assert.NoError(t, err)
	t.Log(aa)

	rawId, err := decodeBase64(aa.Id)
	assert.NoError(t, err)
	ClientDataJSON, err := decodeBase64(aa.Response.ClientDataJSON)
	assert.NoError(t, err)
	AttestationObject, err := decodeBase64(aa.Response.AttestationObject)
	assert.NoError(t, err)
	ccr := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   aa.Id,
				Type: aa.Type,
			},
			RawID:                   rawId,
			ClientExtensionResults:  nil,
			AuthenticatorAttachment: "",
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: ClientDataJSON,
			},
			AttestationObject: AttestationObject,
			Transports:        nil,
		},
		Transports: nil,
	}

	pcc, err := ccr.Parse()
	assert.NoError(t, err)
	t.Log(*pcc)
}

func TestNewServer2(t *testing.T) {
	ss := `{
    "id": "tyE273KHTEpCilALINtyxOTHREojRzBzPWL-xgQgsf8",
    "rawId": "tyE273KHTEpCilALINtyxOTHREojRzBzPWL-xgQgsf8: ",
    "type": "public-key",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAILchNu9yh0xKQopQCyDbcsTkx0RKI0cwcz1i_sYEILH_pQECAyYgASFYIKcPAK4gDlSYcX0FL7WGFb8AhmFVMjTLu9NHXp8N3sorIlggcPltSo7IUg6C3DCTUd3DXLnjHag1e9r5_ul8xqQskfU=",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiU1pFNDRiYWs5cF9HMWZrRVk1RDZDbTRtVUJrNk5BbHFuMENlOVVMVkdqMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0="
    }
}`

	bb := utils.Base64Encode([]byte(ss))
	// t.Log(bb)
	rr, err := utils.Base64Decode(bb)
	assert.NoError(t, err)
	// t.Log(string(rr))

	aa := AA{}
	err = json.Unmarshal(rr, &aa)
	assert.NoError(t, err)
	t.Log(aa)
}

func Test_Register(t *testing.T) {
	// 注册账户 everTx
	everTx := paySchema.Transaction{
		TokenSymbol:  "ETH",
		Action:       "registerWebAuthn",
		From:         "sandy@ever.vision",
		To:           "0x0...0",
		Amount:       "0",
		Fee:          "0",
		FeeRecipient: "0x...",
		Nonce:        "10..0",
		TokenID:      "ethereum-eth-0x00..0",
		ChainType:    "ethereum",
		ChainID:      "1",
		Data: `{
		"user": {
			"name": "sandy@ever.vision",
			"displayName": "sandy@ever.vision",
			"id": "gom7jLr04NuAAQ" // 用于发放给用户的验证码 base64
		},
		"sig": "8svxB9D-l1lHTTyRApfjAhUUxkBbA9pWw6YRShssMN0", // 固定私钥地址签名 user 信息
	}`,
		Version: "v1",
		Sig:     "",
	}
	// webAuthn 签名
	/*
		{
		    "publicKey": {
		        "rp": {
		            "name": "Everpay webauthn",
		            "id": "localhost"
		        },
		        "user": {
		            "name": "sandy@ever.vision",
		            "displayName": "sandy@ever.vision",
		            "id": "gom7jLr04NuAAQ" // 用于发放给用户的验证码 base64
		        },
		        "challenge": everTx.HexHash(),
		        "pubKeyCredParams": [
		            {
		                "type": "public-key",
		                "alg": -7
		            },
		     ...
		        ],
		        "timeout": 300000,
		        "authenticatorSelection": {
		            "requireResidentKey": false,
		            "userVerification": "preferred"
		        }
		    }
		}
	*/
	// 认证器返回签名的信息
	/*
		{
		    "id": "-E-ocXNcQnQEvTjIiE5p1hmn91cZWBQlgJGIhUXSpcA",
		    "rawId": "-E-ocXNcQnQEvTjIiE5p1hmn91cZWBQlgJGIhUXSpcA: ",
		    "type": "public-key",
		    "response": {
		        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIPhPqHFzXEJ0BL04yIhOadYZp_dXGVgUJYCRiIVF0qXApQECAyYgASFYINp375_epjzvcaf9QMV_4x9AYU0SvsanrXXRKmdCJ9g8IlggQmbUoJfL_3ZMN20t9RQ2YWzyNxGu2IZtFSlHrukmAzY=",
		        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOHN2eEI5RC1sMWxIVFR5UkFwZmpBaFVVeGtCYkE5cFd3NllSU2hzc01OMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0="
		    }
		}
	*/

	everTx.Sig = "" // 返回信息的 base64 编码字符串

}

func Test_Transfer(t *testing.T) {
	// 发送交易
	everTx := paySchema.Transaction{
		TokenSymbol:  "USDC",
		Action:       "transfer",
		From:         "sandy@ever.vision",
		To:           "outprog@ever.vision",
		Amount:       "1000000000",
		Fee:          "0",
		FeeRecipient: "0x...",
		Nonce:        "10..0",
		TokenID:      "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		ChainType:    "ethereum",
		ChainID:      "1",
		Data:         "",
		Version:      "v1",
		Sig:          "",
	}

	// webauthn 签名
	/*
		{
		    "publicKey": {
		        "challenge": everTx.HexHash(),
		        "timeout": 300000,
		        "rpId": "localhost",
		        "allowCredentials": [
		            {
		                "type": "public-key",
		                "id": "-E-ocXNcQnQEvTjIiE5p1hmn91cZWBQlgJGIhUXSpcA"
		            }
		        ],
		        "userVerification": "preferred"
		    }
		}
	*/

	// 认证器返回的签名数据
	/*
		{
		    "id": "-E-ocXNcQnQEvTjIiE5p1hmn91cZWBQlgJGIhUXSpcA",
		    "rawId": "-E-ocXNcQnQEvTjIiE5p1hmn91cZWBQlgJGIhUXSpcA: ",
		    "type": "public-key",
		    "response": {
		        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIPhPqHFzXEJ0BL04yIhOadYZp_dXGVgUJYCRiIVF0qXApQECAyYgASFYINp375_epjzvcaf9QMV_4x9AYU0SvsanrXXRKmdCJ9g8IlggQmbUoJfL_3ZMN20t9RQ2YWzyNxGu2IZtFSlHrukmAzY=",
		        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOHN2eEI5RC1sMWxIVFR5UkFwZmpBaFVVeGtCYkE5cFd3NllSU2hzc01OMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0="
		    }
		}
	*/
	everTx.Sig = "" // 返回信息的 base64 编码字符串

}
