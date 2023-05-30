package webauthn_gin

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	paySchema "github.com/everFinance/everpay/pay/schema"
	"github.com/everFinance/goar/utils"
	"github.com/everFinance/goether"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/tidwall/gjson"
	"github.com/zyjblockchain/webauthn-gin/database"
	"github.com/zyjblockchain/webauthn-gin/pay"
	"github.com/zyjblockchain/webauthn-gin/schema"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, HEAD")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func (s *Server) runAPI() {
	r := s.engine
	r.Use(CORSMiddleware())
	stroe := cookie.NewStore([]byte("111222333")) // 用于加密
	r.Use(sessions.Sessions("mysession", stroe))
	v1 := r.Group("/")
	{
		v1.GET("/register/begin/:email", s.beginRegistration)
		v1.POST("/register/finish/:email", s.finishRegistration)
		v1.GET("/login/begin/:email", s.beginLogin)
		v1.POST("/login/finish/:email", s.finishLogin)
	}
	v2 := r.Group("/")
	{
		v2.GET("/register/:email", s.register)
		v2.GET("/account/:email", s.account)
		v2.POST("/tx", s.submitTx)
	}
	r.StaticFile("/", "./views/index.html")
	r.StaticFile("/index.js", "./views/index.js")

	if err := s.engine.Run(":8081"); err != nil {
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
		credCreationOpts.AuthenticatorSelection.UserVerification = protocol.VerificationRequired
		credCreationOpts.AuthenticatorSelection.AuthenticatorAttachment = protocol.Platform
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

	log.Debug("userId", "id", options.Response.User.ID)
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

func (s *Server) register(c *gin.Context) {
	email := c.Param("email")
	// 0. 把 email 都变成小写
	email = strings.ToLower(email)
	// 1. 验证 email 名称是否正确
	if !VerifyEmailFormat(email) {
		log.Error("verify email failed", "email", email)
		internalErrorResponse(c, "email format incorrect")
		return
	}
	// 2. 查看 email 是否已经注册过
	s.locker.Lock()
	defer s.locker.Unlock()
	if _, ok := s.accounts[email]; ok {
		internalErrorResponse(c, "email exist")
		return
	}

	// 3. 为 email 发放验证码
	privateKey := "6c30f80f69711be67452169a3065eeb924c162e7ae1f921083a4d2a181bcfabb"
	signer, err := goether.NewSigner(privateKey)
	if err != nil {
		panic(err)
	}
	// userId + code + email 进行签名
	id := randomUint64()
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, id)
	userId := utils.Base64Encode(buf)

	verifyCode := "123456" // verifyCode 通过邮件发送给注册用户邮箱
	msg := []byte(userId + verifyCode + email)
	sigBy, err := signer.SignMsg(msg)
	if err != nil {
		panic(err)
	}
	sig := hexutil.Encode(sigBy)

	// verifyUser 返回给前端
	c.JSON(200, gin.H{
		"id":  userId,
		"sig": sig,
	})
	return
}

func (s *Server) account(c *gin.Context) {
	email := c.Param("email")
	// 0. 把 email 都变成小写
	email = strings.ToLower(email)

	aa, ok := s.accounts[email]
	if !ok {
		internalErrorResponse(c, "email not exist")
		return
	}
	options, _, err := s.webAuthn.BeginLogin(aa)
	if err != nil {
		log.Error("s.webAuthn.BeginLogin(aa)", "err", err)
		internalErrorResponse(c, err.Error())
		return
	}
	c.JSON(200, gin.H{
		"allowCredentials": options.Response.AllowedCredentials,
	})
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

func (s *Server) submitTx(c *gin.Context) {
	tx := paySchema.Transaction{}
	if err := c.ShouldBindJSON(&tx); err != nil {
		log.Error("c.ShouldBindJSON(&tx)", "err", err)
		internalErrorResponse(c, err.Error())
		return
	}

	if tx.Action == pay.RegisterAuthnAction {
		if err := s.processRegisterTx(tx); err != nil {
			log.Error("s.processRegisterTx(tx)", "err", err)
			internalErrorResponse(c, err.Error())
			return
		}
	} else {
		if err := s.processAuthnTx(tx); err != nil {
			log.Error("s.processAuthnTx(tx)", "err", err)
			internalErrorResponse(c, err.Error())
			return
		}
	}
	c.JSON(http.StatusOK, "ok")
	return
}

func (s *Server) processRegisterTx(tx paySchema.Transaction) error {
	// 1. 交易基本校验
	// 2. 注册 data 校验
	jsData := gjson.Parse(tx.Data)
	emailCode := jsData.Get("mailVerify").Get("code").String()
	codeSig := jsData.Get("mailVerify").Get("sig").String()
	userId := jsData.Get("mailVerify").Get("id").String()

	msg := []byte(userId + emailCode + tx.From)
	hash := accounts.TextHash(msg)
	sig, err := hexutil.Decode(codeSig)
	if err != nil {
		log.Error("hexutil.Decode(codeSig)", "err", err)
		return err
	}
	addr, err := goether.Ecrecover(hash, sig)
	if err != nil {
		log.Error(" goether.Ecrecover(hash,sig)", "err", err)
		return err
	}

	privateKey := "6c30f80f69711be67452169a3065eeb924c162e7ae1f921083a4d2a181bcfabb"
	signer, err := goether.NewSigner(privateKey)
	if err != nil {
		panic(err)
	}
	if addr != signer.Address {
		log.Error("verifyUser failed", "addr", addr.String(), "signer", signer.Address.String())
		return errors.New("verify user failed")
	}

	// 3. webauthn 验证
	sigBy, err := decodeBase64(tx.Sig)
	if err != nil {
		log.Error("decodeBase64(tx.Sig)", "err", err)
		return err
	}
	register := pay.Register{}
	if err = json.Unmarshal(sigBy, &register); err != nil {
		return err
	}

	// 解析 pcc
	rawId, err := decodeBase64(register.RawId)
	if err != nil {
		log.Error("decodeBase64(register.RawId)", "err", err)
		return err
	}
	ClientDataJSON, err := decodeBase64(register.ClientDataJSON)
	if err != nil {
		log.Error("decodeBase64(register.ClientDataJSON)", "err", err)
		return err
	}
	AttestationObject, err := decodeBase64(register.AttestationObject)
	if err != nil {
		log.Error("decodeBase64(register.AttestationObject)", "err", err)
		return err
	}
	ccr := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   userId,
				Type: "public-key",
			},
			RawID:                   rawId,
			ClientExtensionResults:  nil,
			AuthenticatorAttachment: "platform",
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: ClientDataJSON,
			},
			AttestationObject: AttestationObject,
			Transports:        []string{"internal"}, // 代表不能夸平台
		},
		Transports: nil,
	}
	pcc, err := ccr.Parse()
	if err != nil {
		log.Error("ccr.Parse()", "err", err)
		return err
	}
	// 生成凭证
	log.Debug("everHash", "ss", tx.HexHash())
	challenge := utils.Base64Encode([]byte(tx.HexHash())) // todo js 那把和这边 encode 算法不同导致 challenge 不同
	shouldVerifyUser := true
	err = pcc.Verify(challenge, shouldVerifyUser, s.webAuthn.Config.RPID, s.webAuthn.Config.RPOrigins)
	if err != nil {
		log.Error(" pcc.Verify", "err", err)
		return err
	}
	credential, err := webauthn.MakeNewCredential(pcc)
	if err != nil {
		return err // only null
	}

	// 4. add 账户
	s.locker.Lock()
	defer s.locker.Unlock()
	if _, ok := s.accounts[tx.From]; ok {
		return errors.New("account exist")
	}

	aa := NewAA(userId, tx.From)
	aa.AddCredential(*credential)
	s.accounts[aa.WebAuthnName()] = aa
	return nil
}

func (s *Server) processAuthnTx(tx paySchema.Transaction) error {
	// 1. data 基本校验
	// 2. webauthn 签名校验
	sigBy, err := decodeBase64(tx.Sig)
	if err != nil {
		return err
	}
	authn := pay.Authn{}
	if err = json.Unmarshal(sigBy, &authn); err != nil {
		return err
	}

	// 解析 car
	rawId, err := decodeBase64(authn.RawId)
	if err != nil {
		return err
	}
	ClientDataJSON, err := decodeBase64(authn.ClientDataJSON)
	if err != nil {
		return err
	}
	AuthenticatorData, err := decodeBase64(authn.AuthenticatorData)
	if err != nil {
		return err
	}
	Signature, err := decodeBase64(authn.Signature)
	if err != nil {
		return err
	}
	UserHandle, err := decodeBase64(authn.UserHandle)
	if err != nil {
		return err
	}

	car := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   authn.Id,
				Type: "public-key",
			},
			RawID:                   rawId,
			ClientExtensionResults:  nil,
			AuthenticatorAttachment: "platform",
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: ClientDataJSON,
			},
			AuthenticatorData: AuthenticatorData,
			Signature:         Signature,
			UserHandle:        UserHandle,
		},
	}
	pca, err := car.Parse()
	if err != nil {
		return err
	}

	user, ok := s.accounts[tx.From]
	if !ok {
		return errors.New("account not exist")
	}
	session := webauthn.SessionData{
		Challenge:            utils.Base64Encode([]byte(tx.HexHash())),
		UserID:               user.WebAuthnID(),
		UserDisplayName:      user.WebAuthnDisplayName(),
		AllowedCredentialIDs: nil,
		Expires:              time.Time{},
		UserVerification:     protocol.VerificationRequired,
		Extensions:           nil,
	}
	credential, err := s.webAuthn.ValidateLogin(user, session, pca)
	if err != nil {
		return err
	}
	user.AddCredential(*credential)
	// 执行 tx
	log.Info("process tx success...", "everTx", tx.HexHash())

	return nil
}

func internalErrorResponse(c *gin.Context, err string) {
	// internal error
	c.JSON(http.StatusInternalServerError, schema.RespErr{
		Err: err,
	})
}

func decodeBase64(s string) (protocol.URLEncodedBase64, error) {
	bs := &protocol.URLEncodedBase64{}
	err := bs.UnmarshalJSON([]byte(s))
	if err != nil {
		return nil, err
	}
	return *bs, nil
}

func VerifyEmailFormat(email string) bool {
	pattern := `\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*` //匹配电子邮箱
	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}

func UintToBytes(num uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, num)
	return buf
}

func Base64Decode(ss string) ([]byte, error) {
	e := &protocol.URLEncodedBase64{}
	err := e.UnmarshalJSON([]byte(ss))
	if err != nil {
		return nil, err
	}
	return *e, nil
}
