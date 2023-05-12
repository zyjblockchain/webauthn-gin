package webauthn_gin

import (
	"encoding/json"
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

	by, err := json.Marshal(aa)
	assert.NoError(t, err)
	b64by := utils.Base64Encode(by)
	t.Log(b64by)

	// d64by, err := utils.Base64Decode(b64by)
	// assert.NoError(t, err)

	bb := protocol.CredentialCreationResponse{}

	sss := []byte(`{"id":"tyE273KHTEpCilALINtyxOTHREojRzBzPWL-xgQgsf8","rawId":"tyE273KHTEpCilALINtyxOTHREojRzBzPWL-xgQgsf8: ","type":"public-key","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAILchNu9yh0xKQopQCyDbcsTkx0RKI0cwcz1i_sYEILH_pQECAyYgASFYIKcPAK4gDlSYcX0FL7WGFb8AhmFVMjTLu9NHXp8N3sorIlggcPltSo7IUg6C3DCTUd3DXLnjHag1e9r5_ul8xqQskfU=","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiU1pFNDRiYWs5cF9HMWZrRVk1RDZDbTRtVUJrNk5BbHFuMENlOVVMVkdqMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0="}}`)
	err = json.Unmarshal(sss, &bb)
	assert.NoError(t, err)
	t.Log(bb)
}

func TestNewServer2(t *testing.T) {
	sig := "ewogICAgImlkIjogIi1FLW9jWE5jUW5RRXZUaklpRTVwMWhtbjkxY1pXQlFsZ0pHSWhVWFNwY0EiLAogICAgInJhd0lkIjogIi1FLW9jWE5jUW5RRXZUaklpRTVwMWhtbjkxY1pXQlFsZ0pHSWhVWFNwY0E6ICIsCiAgICAidHlwZSI6ICJwdWJsaWMta2V5IiwKICAgICJyZXNwb25zZSI6IHsKICAgICAgICAiYXV0aGVudGljYXRvckRhdGEiOiAiU1pZTjVZZ09qR2gwTkJjUFpIWmdXNF9rcnJtaWhqTEhtVnp6dW9NZGwyTUZBQUFBQUE9PSIsCiAgICAgICAgImNsaWVudERhdGFKU09OIjogImV5SjBlWEJsSWpvaWQyVmlZWFYwYUc0dVoyVjBJaXdpWTJoaGJHeGxibWRsSWpvaVpHNXJkbTV2V1hKdlJWbFdjbDlYYm5ReWNHaHdkRFZXUjFwcVFtaHNWbmQyWkU5amJUSnpiWFV6TkNJc0ltOXlhV2RwYmlJNkltaDBkSEE2THk5c2IyTmhiR2h2YzNRNk9EQTRNQ0lzSW1OeWIzTnpUM0pwWjJsdUlqcG1ZV3h6WlgwPSIsCiAgICAgICAgInNpZ25hdHVyZSI6ICJNRVVDSUZIc24zcHJnbHoydzhIMjF3bUlPZWpvLU9fZjlYSUxSSmNIRm1VNWYwRUJBaUVBaW9NcjdDMDJualhNdnJOLVl3b3A0T0pNa2Q4Rmd3ZW5IN1FOT09sSWQ4QT0iLAogICAgICAgICJ1c2VySGFuZGxlIjogImdvbTdqTHIwNE51QUFRPT0iCiAgICB9Cn0"

	sigBy, err := utils.Base64Decode(sig)
	assert.NoError(t, err)
	aa := protocol.CredentialAssertionResponse{}
	err = json.Unmarshal(sigBy, &aa)
	assert.NoError(t, err)
	t.Log(aa)
}
