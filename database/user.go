package database

import (
	"crypto/rand"
	"encoding/binary"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"strings"
	"time"
)

type User struct {
	ID          uint64    `gorm:"primary_key"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	Email       string    `gorm:"unique;not null"` // email is unique
	DisplayName string
	// Credentials stored in json in the DB
	Credentials ColumnCredentials `json:"credentials,omitempty" gorm:"type:VARCHAR(4096)"`
}

// NewUser creates and returns a new User
func NewUser(email string) *User {
	displayName := strings.Split(email, "@")[0]
	user := &User{}
	user.ID = randomUint64()
	user.Email = email
	user.DisplayName = displayName
	// user.Credentials = []webauthn.Credential{}

	return user
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

func (u User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.ID))
	return buf
}

func (u User) WebAuthnName() string {
	return u.Email
}

func (u User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u User) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the user
func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all a user's Credentials
func (u User) CredentialExcludeList() (credentialExcludeList []protocol.CredentialDescriptor) {
	for _, cred := range u.Credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}
