package serviceprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/chanxuehong/util/security"
	"github.com/chanxuehong/wechat/internal/debug/api"
	"github.com/chanxuehong/wechat/internal/debug/callback"
	"github.com/chanxuehong/wechat/internal/util"
	"github.com/chanxuehong/wechat/mp/core"
	wechatUtil "github.com/chanxuehong/wechat/util"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// 检查 AccessTokenServer 的接口实现
var _ core.AccessTokenServer = (*DefaultComponentAccessTokenServer)(nil)

// DefaultComponentAccessTokenServer 实现了 AccessTokenServer 接口.
//  NOTE:
//  1. 用于单进程环境.
//  2. 因为 DefaultComponentAccessTokenServer 同时也是一个简单的中控服务器, 而不是仅仅实现 AccessTokenServer 接口,
//     所以整个系统只能存在一个 DefaultComponentAccessTokenServer 实例!

type tokenBucket struct {
	currentToken string
	lastToken    string
}

type aesKeyBucket struct {
	currentAESKey []byte
	lastAESKey    []byte
}

type verifyTicketBucket struct {
	currentTicket string
	lastTicket    string
}

type DefaultComponentAccessTokenServer struct {
	appId     string
	appSecret string

	tokenBucketPtrMutex sync.Mutex     // used only by writers
	tokenBucketPtr      unsafe.Pointer // *tokenBucket

	aesKeyBucketPtrMutex sync.Mutex     // used only by writers
	aesKeyBucketPtr      unsafe.Pointer // *aesKeyBucket

	verifyTicketBucketPtrMutex sync.Mutex // used only by writers
	verifyTicketBucketPtr      unsafe.Pointer

	httpClient               *http.Client
	refreshTokenRequestChan  chan string             // chan currentToken
	refreshTokenResponseChan chan refreshTokenResult // chan {token, err}
	tokenCache               unsafe.Pointer          // *accessToken
}

// NewDefaultComponentAccessTokenServer 创建一个新的 DefaultComponentAccessTokenServer, 如果 httpClient == nil 则默认使用 util.DefaultHttpClient.

//https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/api/component_access_token.html

// NewServer 创建一个新的 Server.
//  componentAppId:		必须; 平台型服务商的componentAppAppId;
//  componentAppSecret: 必须; 平台型服务商的componentAppSecret;
//  token:        		必须; 平台型服务商的用于验证签名的token;
//  base64AESKey: 		可选; aes加密解密key, 43字节长(base64编码, 去掉了尾部的'='), 安全模式必须设置;
//  httpClient:      	可选; http request client;
//  options				可选; options[0]:true enable,false disabled tokenUpdateDaemon

func NewDefaultComponentAccessTokenServer(componentAppId, componentAppSecret, token, base64AESKey string, httpClient *http.Client, options ...interface{}) (srv *DefaultComponentAccessTokenServer) {
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	if token == "" {
		panic("empty token")
	}
	var (
		aesKey                  []byte
		err                     error
		enableTokenUpdateDaemon bool = true
	)
	if base64AESKey != "" {
		if len(base64AESKey) != 43 {
			panic("the length of base64AESKey must equal to 43")
		}
		aesKey, err = base64.StdEncoding.DecodeString(base64AESKey + "=")
		if err != nil {
			panic(fmt.Sprintf("Decode base64AESKey:%s failed", base64AESKey))
		}
	}

	srv = &DefaultComponentAccessTokenServer{
		appId:                    componentAppId,
		appSecret:                componentAppSecret,
		tokenBucketPtr:           unsafe.Pointer(&tokenBucket{currentToken: token}),
		aesKeyBucketPtr:          unsafe.Pointer(&aesKeyBucket{currentAESKey: aesKey}),
		httpClient:               httpClient,
		refreshTokenRequestChan:  make(chan string),
		refreshTokenResponseChan: make(chan refreshTokenResult),
	}
	if len(options) > 0 {
		if val, ok := options[0].(bool); ok && val == false {
			enableTokenUpdateDaemon = false
		}
	}
	if enableTokenUpdateDaemon {
		go srv.tokenUpdateDaemon(time.Hour * 24 * time.Duration(100+rand.Int63n(200)))
	}
	return
}

func (srv *DefaultComponentAccessTokenServer) getVerifyTicket() (currentTicket, lastTicket string) {
	if p := (*verifyTicketBucket)(atomic.LoadPointer(&srv.verifyTicketBucketPtr)); p != nil {
		return p.currentTicket, p.lastTicket
	}
	return
}

func (srv *DefaultComponentAccessTokenServer) SetVerifyTicket(ticket string) (err error) {
	if ticket == "" {
		return errors.New("empty ticket")
	}

	srv.verifyTicketBucketPtrMutex.Lock()
	defer srv.verifyTicketBucketPtrMutex.Unlock()

	currentTicket, _ := srv.getVerifyTicket()
	if ticket == currentTicket {
		return
	}

	bucket := verifyTicketBucket{
		currentTicket: ticket,
		lastTicket:    currentTicket,
	}
	atomic.StorePointer(&srv.verifyTicketBucketPtr, unsafe.Pointer(&bucket))
	return
}

func (srv *DefaultComponentAccessTokenServer) removeLastTicket(lastTicket string) {
	srv.verifyTicketBucketPtrMutex.Lock()
	defer srv.verifyTicketBucketPtrMutex.Unlock()

	currentTicket2, lastTicket2 := srv.getVerifyTicket()
	if lastTicket != lastTicket2 {
		return
	}

	bucket := verifyTicketBucket{
		currentTicket: currentTicket2,
	}
	atomic.StorePointer(&srv.verifyTicketBucketPtr, unsafe.Pointer(&bucket))
	return
}

func (srv *DefaultComponentAccessTokenServer) getToken() (currentToken, lastToken string) {
	if p := (*tokenBucket)(atomic.LoadPointer(&srv.tokenBucketPtr)); p != nil {
		return p.currentToken, p.lastToken
	}
	return
}

func (srv *DefaultComponentAccessTokenServer) SetToken(token string) (err error) {
	if token == "" {
		return errors.New("empty token")
	}

	srv.tokenBucketPtrMutex.Lock()
	defer srv.tokenBucketPtrMutex.Unlock()

	currentToken, _ := srv.getToken()
	if token == currentToken {
		return
	}

	bucket := tokenBucket{
		currentToken: token,
		lastToken:    currentToken,
	}
	atomic.StorePointer(&srv.tokenBucketPtr, unsafe.Pointer(&bucket))
	return
}

func (srv *DefaultComponentAccessTokenServer) removeLastToken(lastToken string) {
	srv.tokenBucketPtrMutex.Lock()
	defer srv.tokenBucketPtrMutex.Unlock()

	currentToken2, lastToken2 := srv.getToken()
	if lastToken != lastToken2 {
		return
	}

	bucket := tokenBucket{
		currentToken: currentToken2,
	}
	atomic.StorePointer(&srv.tokenBucketPtr, unsafe.Pointer(&bucket))
	return
}

func (srv *DefaultComponentAccessTokenServer) getAESKey() (currentAESKey, lastAESKey []byte) {
	if p := (*aesKeyBucket)(atomic.LoadPointer(&srv.aesKeyBucketPtr)); p != nil {
		return p.currentAESKey, p.lastAESKey
	}
	return
}

// SetAESKey 设置aes加密解密key.
//  base64AESKey: aes加密解密key, 43字节长(base64编码, 去掉了尾部的'=').
func (srv *DefaultComponentAccessTokenServer) SetAESKey(base64AESKey string) (err error) {
	if len(base64AESKey) != 43 {
		return errors.New("the length of base64AESKey must equal to 43")
	}
	aesKey, err := base64.StdEncoding.DecodeString(base64AESKey + "=")
	if err != nil {
		return
	}

	srv.aesKeyBucketPtrMutex.Lock()
	defer srv.aesKeyBucketPtrMutex.Unlock()

	currentAESKey, _ := srv.getAESKey()
	if bytes.Equal(aesKey, currentAESKey) {
		return
	}

	bucket := aesKeyBucket{
		currentAESKey: aesKey,
		lastAESKey:    currentAESKey,
	}
	atomic.StorePointer(&srv.aesKeyBucketPtr, unsafe.Pointer(&bucket))
	return
}

func (srv *DefaultComponentAccessTokenServer) removeLastAESKey(lastAESKey []byte) {
	srv.aesKeyBucketPtrMutex.Lock()
	defer srv.aesKeyBucketPtrMutex.Unlock()

	currentAESKey2, lastAESKey2 := srv.getAESKey()
	if !bytes.Equal(lastAESKey, lastAESKey2) {
		return
	}

	bucket := aesKeyBucket{
		currentAESKey: currentAESKey2,
	}
	atomic.StorePointer(&srv.aesKeyBucketPtr, unsafe.Pointer(&bucket))
	return
}

func (srv *DefaultComponentAccessTokenServer) HandleAuthEventMsg(r *http.Request, query url.Values) (err error) {
	callback.DebugPrintRequest(r)
	if query == nil {
		query = r.URL.Query()
	}

	switch r.Method {
	case "POST": // 推送消息(事件)
		switch encryptType := query.Get("encrypt_type"); encryptType {
		case "aes":
			haveSignature := query.Get("signature")
			if haveSignature == "" {
				return
			}
			haveMsgSignature := query.Get("msg_signature")
			if haveMsgSignature == "" {
				return
			}
			timestampString := query.Get("timestamp")
			if timestampString == "" {
				return
			}
			_, err = strconv.ParseInt(timestampString, 10, 64)
			if err != nil {
				err = fmt.Errorf("can not parse timestamp query parameter %q to int64", timestampString)
				return
			}
			nonce := query.Get("nonce")
			if nonce == "" {
				return
			}

			var token string
			currentToken, lastToken := srv.getToken()
			if currentToken == "" {
				err = errors.New("token was not set for Server, see NewServer function or Server.SetToken method")
				return
			}
			token = currentToken
			wantSignature := util.Sign(token, timestampString, nonce)
			if !security.SecureCompareString(haveSignature, wantSignature) {
				if lastToken == "" {
					err = fmt.Errorf("check signature failed, have: %s, want: %s", haveSignature, wantSignature)
					return
				}
				token = lastToken
				wantSignature = util.Sign(token, timestampString, nonce)
				if !security.SecureCompareString(haveSignature, wantSignature) {
					err = fmt.Errorf("check signature failed, have: %s, want: %s", haveSignature, wantSignature)
					return
				}
			} else {
				if lastToken != "" {
					srv.removeLastToken(lastToken)
				}
			}

			buffer := textBufferPool.Get().(*bytes.Buffer)
			buffer.Reset()
			defer textBufferPool.Put(buffer)

			if _, err = buffer.ReadFrom(r.Body); err != nil {
				return
			}
			requestBodyBytes := buffer.Bytes()

			var requestHttpBody EncryptBody
			if err = XmlUnmarshal(requestBodyBytes, &requestHttpBody); err != nil {
				return
			}

			haveToUserName := requestHttpBody.ToUserName

			wantMsgSignature := util.MsgSign(token, timestampString, nonce, string(requestHttpBody.Base64EncryptedMsg))
			if !security.SecureCompareString(haveMsgSignature, wantMsgSignature) {
				err = fmt.Errorf("check msg_signature failed, have: %s, want: %s", haveMsgSignature, wantMsgSignature)
				return
			}

			encryptedMsg := make([]byte, base64.StdEncoding.DecodedLen(len(requestHttpBody.Base64EncryptedMsg)))
			encryptedMsgLen, err := base64.StdEncoding.Decode(encryptedMsg, requestHttpBody.Base64EncryptedMsg)
			if err != nil {
				return
			}
			encryptedMsg = encryptedMsg[:encryptedMsgLen]

			var aesKey []byte
			currentAESKey, lastAESKey := srv.getAESKey()
			if currentAESKey == nil {
				err = errors.New("aes key was not set for Server, see NewServer function or Server.SetAESKey method")
				return
			}
			aesKey = currentAESKey
			_, msgPlaintext, haveAppIdBytes, err := util.AESDecryptMsg(encryptedMsg, aesKey)
			if err != nil {
				if lastAESKey == nil {
					return
				}
				aesKey = lastAESKey
				_, msgPlaintext, haveAppIdBytes, err = util.AESDecryptMsg(encryptedMsg, aesKey)
				if err != nil {
					return
				}
			} else {
				if lastAESKey != nil {
					srv.removeLastAESKey(lastAESKey)
				}
			}
			callback.DebugPrintPlainRequestMessage(msgPlaintext)

			haveAppId := string(haveAppIdBytes)
			wantAppId := srv.appId
			if wantAppId != "" && !security.SecureCompareString(haveAppId, wantAppId) {
				err = fmt.Errorf("the message AppId mismatch, have: %s, want: %s", haveAppId, wantAppId)
				return
			}

			var mixedMsg core.MixedServiceProviderMsg
			if err = xml.Unmarshal(msgPlaintext, &mixedMsg); err != nil {
				return
			}
			if haveToUserName != mixedMsg.ToUserName {
				err = fmt.Errorf("the message ToUserName mismatch between ciphertext and plaintext, %q != %q",
					haveToUserName, mixedMsg.ToUserName)
				return
			}
			//set
			if mixedMsg.InfoType == "component_verify_ticket" {
				err = srv.SetVerifyTicket(mixedMsg.ComponentVerifyTicket)
			}

		case "", "raw":
			haveSignature := query.Get("signature")
			if haveSignature == "" {
				return
			}
			timestampString := query.Get("timestamp")
			if timestampString == "" {
				return
			}
			_, err = strconv.ParseInt(timestampString, 10, 64)
			if err != nil {
				err = fmt.Errorf("can not parse timestamp query parameter %q to int64", timestampString)
				return
			}
			nonce := query.Get("nonce")
			if nonce == "" {
				return
			}

			var token string
			currentToken, lastToken := srv.getToken()
			if currentToken == "" {
				err = errors.New("token was not set for Server, see NewServer function or Server.SetToken method")
				return
			}
			token = currentToken
			wantSignature := util.Sign(token, timestampString, nonce)
			if !security.SecureCompareString(haveSignature, wantSignature) {
				if lastToken == "" {
					err = fmt.Errorf("check signature failed, have: %s, want: %s", haveSignature, wantSignature)
					return
				}
				token = lastToken
				wantSignature = util.Sign(token, timestampString, nonce)
				if !security.SecureCompareString(haveSignature, wantSignature) {
					err = fmt.Errorf("check signature failed, have: %s, want: %s", haveSignature, wantSignature)
					return
				}
			} else {
				if lastToken != "" {
					srv.removeLastToken(lastToken)
				}
			}

			msgPlaintext, err := ioutil.ReadAll(r.Body)
			if err != nil {
				return
			}
			callback.DebugPrintPlainRequestMessage(msgPlaintext)

			var mixedMsg core.MixedMsg
			if err = xml.Unmarshal(msgPlaintext, &mixedMsg); err != nil {
				return
			}
			if mixedMsg.InfoType == "component_verify_ticket" {
				err = srv.SetVerifyTicket(mixedMsg.ComponentVerifyTicket)
			}
		default:
			err = errors.New("unknown encrypt_type: " + encryptType)
			return
		}

	case "GET": // 验证回调URL是否有效
		haveSignature := query.Get("signature")
		if haveSignature == "" {
			return
		}
		timestamp := query.Get("timestamp")
		if timestamp == "" {
			return
		}
		nonce := query.Get("nonce")
		if nonce == "" {
			return
		}
		echostr := query.Get("echostr")
		if echostr == "" {
			return
		}

		var token string
		currentToken, lastToken := srv.getToken()
		if currentToken == "" {
			err = errors.New("token was not set for Server, see NewServer function or Server.SetToken method")
			return
		}
		token = currentToken
		wantSignature := util.Sign(token, timestamp, nonce)
		if !security.SecureCompareString(haveSignature, wantSignature) {
			if lastToken == "" {
				err = fmt.Errorf("check signature failed, have: %s, want: %s", haveSignature, wantSignature)
				return
			}
			token = lastToken
			wantSignature = util.Sign(token, timestamp, nonce)
			if !security.SecureCompareString(haveSignature, wantSignature) {
				err = fmt.Errorf("check signature failed, have: %s, want: %s", haveSignature, wantSignature)
				return
			}
		} else {
			if lastToken != "" {
				srv.removeLastToken(lastToken)
			}
		}
		return
	}
	return
}

func (srv *DefaultComponentAccessTokenServer) IID01332E16DF5011E5A9D5A4DB30FED8E1() {}

func (srv *DefaultComponentAccessTokenServer) Token() (token string, err error) {
	if p := (*accessToken)(atomic.LoadPointer(&srv.tokenCache)); p != nil {
		return p.Token, nil
	}
	return srv.RefreshToken("")
}

func (srv *DefaultComponentAccessTokenServer) Ticket() (ticket string, err error) {
	if p := (*verifyTicketBucket)(atomic.LoadPointer(&srv.verifyTicketBucketPtr)); p != nil {
		return p.currentTicket, nil
	}
	return
}

// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/api/pre_auth_code.html
func (srv *DefaultComponentAccessTokenServer) PreAuthCode() (code string, err error) {
	token, err := srv.Token()
	if err != nil {
		return
	}
	urlStr := "https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token=" + token
	vals := make(map[string]string, 0)
	vals["component_access_token"] = token
	vals["component_appid"] = srv.appId
	valsBytArr, err := json.Marshal(vals)
	if err != nil {
		return
	}
	api.DebugPrintGetRequest(urlStr)
	var result struct {
		Error
		PreAuthCode string `json:"pre_auth_code,omitempty"`
		ExpiresIn   int    `json:"expires_in,omitempty"`
	}
	err = httpPostJSON(srv.httpClient, urlStr, valsBytArr, &result)
	if err != nil {
		return
	}
	if result.ErrCode != ErrCodeOK {
		err = &result.Error
		return
	}
	code = result.PreAuthCode
	return
}

type refreshTokenResult struct {
	token string
	err   error
}

func (srv *DefaultComponentAccessTokenServer) RefreshToken(currentToken string) (token string, err error) {
	srv.refreshTokenRequestChan <- currentToken
	rslt := <-srv.refreshTokenResponseChan
	return rslt.token, rslt.err
}

func (srv *DefaultComponentAccessTokenServer) tokenUpdateDaemon(initTickDuration time.Duration) {
	tickDuration := initTickDuration

newTickDuration:
	ticker := time.NewTicker(tickDuration)
	for {
		select {
		case currentToken := <-srv.refreshTokenRequestChan:
			accessToken, cached, err := srv.updateToken(currentToken)
			if err != nil {
				srv.refreshTokenResponseChan <- refreshTokenResult{err: err}
				break
			}
			srv.refreshTokenResponseChan <- refreshTokenResult{token: accessToken.Token}
			if !cached {
				tickDuration = time.Duration(accessToken.ExpiresIn) * time.Second
				ticker.Stop()
				goto newTickDuration
			}

		case <-ticker.C:
			accessToken, _, err := srv.updateToken("")
			if err != nil {
				break
			}
			newTickDuration := time.Duration(accessToken.ExpiresIn) * time.Second
			if abs(tickDuration-newTickDuration) > time.Second*5 {
				tickDuration = newTickDuration
				ticker.Stop()
				goto newTickDuration
			}
		}
	}
}

func abs(x time.Duration) time.Duration {
	if x >= 0 {
		return x
	}
	return -x
}

// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/api/component_access_token.html
type accessToken struct {
	Token     string `json:"component_access_token"`
	ExpiresIn int64  `json:"expires_in"`
}

// updateToken 从微信服务器获取新的 access_token 并存入缓存, 同时返回该 access_token.
func (srv *DefaultComponentAccessTokenServer) updateToken(currentToken string) (token *accessToken, cached bool, err error) {
	if currentToken != "" {
		if p := (*accessToken)(atomic.LoadPointer(&srv.tokenCache)); p != nil && currentToken != p.Token {
			return p, true, nil // 无需更改 p.ExpiresIn 参数值, cached == true 时用不到
		}
	}
	verifyTicket, err := srv.Ticket()
	if err != nil {
		return
	}
	urlStr := "https://api.weixin.qq.com/cgi-bin/component/api_component_token"
	api.DebugPrintGetRequest(urlStr)
	vals := make(map[string]string, 0)
	vals["component_appid"] = srv.appId
	vals["component_appsecret"] = srv.appSecret
	vals["component_verify_ticket"] = verifyTicket
	valByteArr, err := json.Marshal(vals)
	if err != nil {
		return
	}
	var result struct {
		Error
		accessToken
	}
	err = httpPostJSON(srv.httpClient, urlStr, valByteArr, &result)
	if err != nil {
		atomic.StorePointer(&srv.tokenCache, nil)
		return
	}
	if result.ErrCode != ErrCodeOK {
		atomic.StorePointer(&srv.tokenCache, nil)
		err = &result.Error
		return
	}

	// 由于网络的延时, access_token 过期时间留有一个缓冲区
	switch {
	case result.ExpiresIn > 31556952: // 60*60*24*365.2425
		atomic.StorePointer(&srv.tokenCache, nil)
		err = errors.New("expires_in too large: " + strconv.FormatInt(result.ExpiresIn, 10))
		return
	case result.ExpiresIn > 60*60:
		result.ExpiresIn -= 60 * 10
	case result.ExpiresIn > 60*30:
		result.ExpiresIn -= 60 * 5
	case result.ExpiresIn > 60*5:
		result.ExpiresIn -= 60
	case result.ExpiresIn > 60:
		result.ExpiresIn -= 10
	default:
		atomic.StorePointer(&srv.tokenCache, nil)
		err = errors.New("expires_in too small: " + strconv.FormatInt(result.ExpiresIn, 10))
		return
	}

	tokenCopy := result.accessToken
	atomic.StorePointer(&srv.tokenCache, unsafe.Pointer(&tokenCopy))
	token = &tokenCopy
	return
}
