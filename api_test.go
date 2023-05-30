package webauthn_gin

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	paySchema "github.com/everFinance/everpay/pay/schema"
	"github.com/everFinance/goar/utils"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/zyjblockchain/webauthn-gin/pay"
	"strings"
	"testing"
)

type AAs struct {
	Id       string
	RawId    string `json:"rawId"`
	Type     string
	Response struct {
		AttestationObject string `json:"attestationObject"`
		ClientDataJSON    string `json:"clientDataJSON"`
	} `json:"response"`
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

	aa := AAs{}
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
		Action:       "registerAcc",
		From:         "sandy@ever.vision",
		To:           "sandy@ever.vision",
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
			"code": "123456", // 邮箱验证码
			"verify" : "0xc86e4b15724bb4c4342dcb35a8d02bf865be4b649d37cc21cce67f2267218ef7" // 固定私钥地址签名 user 信息
		},
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
		        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA==",
		        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZG5rdm5vWXJvRVlWcl9XbnQycGhwdDVWR1pqQmhsVnd2ZE9jbTJzbXUzNCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=",
		        "signature": "MEUCIFHsn3prglz2w8H21wmIOejo-O_f9XILRJcHFmU5f0EBAiEAioMr7C02njXMvrN-Ywop4OJMkd8FgwenH7QNOOlId8A=",
		        "userHandle": "gom7jLr04NuAAQ=="
		    }
		}
	*/
	everTx.Sig = "" // 返回信息的 base64 编码字符串

}

func TestNewServer3(t *testing.T) {
	nn := 3961173940445684860
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(nn))
	t.Log(string(buf))

	num, a := binary.Uvarint(buf)
	t.Log(a)
	t.Log(num)
}

func TestVerifyEmailFormat(t *testing.T) {
	nn := uint64(16413053965818424568)
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(nn))
	ss := base64.RawURLEncoding.EncodeToString(buf)
	t.Log(ss)

	id, _ := binary.Uvarint(buf)
	t.Log(id)
	t.Log(randomUint64())
}

func TestCORSMiddleware(t *testing.T) {
	sig := "eyJpZCI6e30sInJhd0lkIjoiUDQweXo0ZElqVFJvMUVCalYyWmJ4YjBsSkczRFVuQXpXZ20wT0ZkQlBqZz0iLCJhdHRlc3RhdGlvbk9iamVjdCI6IiIsImNsaWVudERhdGFKU09OIjoiIn0="

	e := &protocol.URLEncodedBase64{}
	err := e.UnmarshalJSON([]byte(sig))
	assert.NoError(t, err)
	ee := []byte(*e)
	t.Log(string(ee))
	r := pay.Register{}
	err = json.Unmarshal(ee, &r)
	assert.NoError(t, err)
	t.Log(r)
}

func TestUintToBytes(t *testing.T) {
	// sig := "eyJpZCI6e30sInJhd0lkIjoiUDQweXo0ZElqVFJvMUVCalYyWmJ4YjBsSkczRFVuQXpXZ20wT0ZkQlBqZz0iLCJhdHRlc3RhdGlvbk9iamVjdCI6IiIsImNsaWVudERhdGFKU09OIjoiIn0="
	// by, err := Base64Decode(sig)
	// assert.NoError(t, err)
	// t.Log(string(by))
	everTx := "0xeede6d4c84762407cf6ee03e9df7781b38cb7374fc347941a82743a8c955cd09"
	ss := utils.Base64Encode([]byte(everTx))
	t.Log(ss)
}
