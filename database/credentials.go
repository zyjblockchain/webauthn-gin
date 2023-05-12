package database

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jinzhu/gorm"
	"gorm.io/gorm/schema"
)

// ColumnCredentials a type for a gorm model column whose value is json string in the DB but []webauthn.Credential while in memory
type ColumnCredentials []webauthn.Credential

// Value when the DB driver writes to DB
func (c ColumnCredentials) Value() (driver.Value, error) {
	str, err := json.Marshal(c)
	return driver.Value(str), err
}

// Scan when the DB driver reads from the DB
func (c *ColumnCredentials) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("CredentialColumn value is not []byte")
	}
	creds := []webauthn.Credential{}
	err := json.Unmarshal(b, &creds)
	*c = creds

	return err
}

func (c *ColumnCredentials) GormDataType() string {
	return "json"
}

func (c *ColumnCredentials) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	switch db.Dialect().GetName() {
	case "mysql", "sqlite":
		return "JSON"
	case "postgres":
		return "JSONB"
	}
	return ""
}
