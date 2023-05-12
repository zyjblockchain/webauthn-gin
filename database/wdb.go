package database

import (
	"github.com/everFinance/go-everpay/common"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Wdb struct {
	Db *gorm.DB
}

var log = common.NewLog("webauthn-gin-db")

func NewDB(dsn string) *Wdb {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger:          logger.Default.LogMode(logger.Silent),
		CreateBatchSize: 200,
	})
	if err != nil {
		panic(err)
	}
	log.Info("connect mysql db success")

	w := &Wdb{Db: db}
	err = w.migrate()
	if err != nil {
		panic(err)
	}
	return w
}

func (w *Wdb) migrate() error {
	return w.Db.AutoMigrate(&User{})
}

func (w *Wdb) GetUser(emailName string) (*User, error) {
	result := User{}
	err := w.Db.Model(&User{}).Where("email = ?", emailName).First(&result).Error
	return &result, err
}

func (w *Wdb) InsertUser(user *User) error {
	return w.Db.Create(user).Error
}

func (w *Wdb) UpdateUserCredentials(user *User) error {
	return w.Db.Model(&User{}).Where("id = ?", user.ID).Update("credentials", user.Credentials).Error
}
