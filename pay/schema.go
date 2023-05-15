package pay

type Register struct {
	Id                string `json:"id"`
	RawId             string `json:"rawId"` // 二进制形式的凭证Id
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

type Login struct {
	Id                string `json:"id"`
	RawId             string `json:"rawId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}
