package webauthn_gin

import (
	"github.com/everFinance/go-everpay/common"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/zyjblockchain/webauthn-gin/database"
)

var log = common.NewLog("webauthn-gin")

type Server struct {
	engine   *gin.Engine
	webAuthn *webauthn.WebAuthn
	wdb      *database.Wdb
}

func NewServer(dsn string) *Server {
	webAuthn, err := webauthn.New(&webauthn.Config{
		RPID:                  "localhost",
		RPDisplayName:         "Everpay webauthn",
		RPOrigins:             []string{"http://localhost:8080"},
		AttestationPreference: "",
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
		Debug:                false,
		EncodeUserIDAsString: false,
		Timeouts:             webauthn.TimeoutsConfig{},
	})
	if err != nil {
		panic(err)
	}
	return &Server{
		engine:   gin.Default(),
		webAuthn: webAuthn,
		wdb:      database.NewDB(dsn),
	}
}

func (s *Server) Run() {
	go s.runAPI()
}
