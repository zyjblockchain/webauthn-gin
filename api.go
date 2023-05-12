package webauthn_gin

import (
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/zyjblockchain/webauthn-gin/database"
	"github.com/zyjblockchain/webauthn-gin/schema"
	"io"
	"net/http"
)

func (s *Server) runAPI() {
	r := s.engine
	stroe := cookie.NewStore([]byte("111222333")) // 用于加密
	r.Use(sessions.Sessions("mysession", stroe))
	v1 := r.Group("/")
	{
		v1.GET("/register/begin/:email", s.beginRegistration)
		v1.POST("/register/finish/:email", s.finishRegistration)
		v1.GET("/login/begin/:email", s.beginLogin)
		v1.POST("/login/finish/:email", s.finishLogin)
	}
	r.StaticFile("/", "./views/index.html")
	r.StaticFile("/index.js", "./views/index.js")

	if err := s.engine.Run(":8080"); err != nil {
		panic(err)
	}
}

func (s *Server) beginRegistration(c *gin.Context) {
	email := c.Param("email") // must be email
	log.Debug("Begin Registration", "email", email)

	// get user
	user, err := s.wdb.GetUser(email)
	if err != nil { // not exist
		log.Error("s.wdb.GetUser(email)", "err", err)
		user = database.NewUser(email)
		// insert mysql
		if err = s.wdb.InsertUser(user); err != nil {
			internalErrorResponse(c, err.Error())
			return
		}
	}

	// generate register options
	// add excludeList credential
	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}
	options, sessionData, err := s.webAuthn.BeginRegistration(
		user,
		registerOptions,
	)
	if err != nil {
		internalErrorResponse(c, err.Error())
		return
	}
	session := sessions.Default(c)
	data, _ := json.Marshal(sessionData)
	session.Set("register", data)
	session.Save()
	log.Debug("sessionData", "data", *sessionData)

	c.JSON(200, options)
}

func (s *Server) finishRegistration(c *gin.Context) {
	email := c.Param("email") // must be email
	log.Debug("Finish Registration", "email", email)

	// get user
	user, err := s.wdb.GetUser(email)
	if err != nil {
		internalErrorResponse(c, err.Error())
		return
	}
	// load sessionData
	session := sessions.Default(c)
	data := session.Get("register")
	sessionData := webauthn.SessionData{}
	if err = json.Unmarshal(data.([]byte), &sessionData); err != nil {
		internalErrorResponse(c, err.Error())
		return
	}
	bby, err := io.ReadAll(c.Request.Body)
	if err != nil {
		panic(err)
	}
	log.Warn("body", "bby: ", string(bby))
	// reader := bytes.NewReader(bby)
	credential, err := s.webAuthn.FinishRegistration(user, sessionData, c.Request)
	if err != nil {
		internalErrorResponse(c, err.Error())
		return
	}

	// add credential to user
	user.AddCredential(*credential)
	if err = s.wdb.UpdateUserCredentials(user); err != nil {
		internalErrorResponse(c, err.Error())
		return
	}
	c.JSON(200, "Registration Success")
}

func (s *Server) beginLogin(c *gin.Context) {
	email := c.Param("email") // must be email
	log.Debug("beginLogin", "email", email)

	// get user
	user, err := s.wdb.GetUser(email)
	if err != nil {
		internalErrorResponse(c, err.Error())
		return
	}
	options, sessionData, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		internalErrorResponse(c, err.Error())
		return
	}

	session := sessions.Default(c)
	data, _ := json.Marshal(sessionData)
	session.Set("authentication", data)
	session.Save()

	c.JSON(200, options)

}

func (s *Server) finishLogin(c *gin.Context) {
	email := c.Param("email") // must be email
	log.Debug("finishLogin", "email", email)

	// get user
	user, err := s.wdb.GetUser(email)
	if err != nil {
		internalErrorResponse(c, err.Error())
		return
	}

	// load sessionData
	session := sessions.Default(c)
	data := session.Get("authentication")
	sessionData := webauthn.SessionData{}
	if err = json.Unmarshal(data.([]byte), &sessionData); err != nil {
		internalErrorResponse(c, err.Error())
		return
	}

	_, err = s.webAuthn.FinishLogin(user, sessionData, c.Request)
	if err != nil {
		internalErrorResponse(c, err.Error())
		return
	}
	c.JSON(200, "Login Success")
}

func internalErrorResponse(c *gin.Context, err string) {
	// internal error
	c.JSON(http.StatusInternalServerError, schema.RespErr{
		Err: err,
	})
}
