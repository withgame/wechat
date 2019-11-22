/*
 * Copyright (c) 2019. 深圳青木文化传播有限公司.
 */

package serviceprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/astaxie/beego/logs"
	"github.com/chanxuehong/util/security"
	"gopkg.in/chanxuehong/wechat.v2/internal/debug/callback"
	"gopkg.in/chanxuehong/wechat.v2/internal/util"
	"gopkg.in/chanxuehong/wechat.v2/mp/core"
	wechatUtil "gopkg.in/chanxuehong/wechat.v2/util"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
)

type ItemList struct {
	Address     string `json:"address"`
	Tag         string `json:"tag"`
	FirstClass  string `json:"first_class"`
	SecondClass string `json:"second_class"`
	FirstId     int    `json:"first_id"`
	SecondId    int    `json:"second_id"`
	Title       string `json:"title"`
}

type SubCat struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Cat struct {
	FirstCatId  int      `json:"first"`
	SecondCatId int      `json:"second"`
	Cats        []SubCat `json:"certicates"`
}

// 设置服务器域名
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/Server_Address_Configuration.html
func (clt *Client) ModifyDomain(authorizerAccessToken, incompleteURL string, action ActionType, domains map[string][]string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/modify_domain?access_token="
	}
	if len(domains["req"]) == 0 || len(domains["ws"]) == 0 || len(domains["upload"]) == 0 || len(domains["download"]) == 0 {
		err = errors.New("missing required params")
		return
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	vals := make(map[string]interface{}, 0)
	vals["action"] = string(action)
	vals["requestdomain"] = domains["req"]
	vals["wsrequestdomain"] = domains["ws"]
	vals["uploaddomain"] = domains["upload"]
	vals["downloaddomain"] = domains["download"]
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + url.QueryEscape(authorizerAccessToken)
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 上传小程序代码
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/code/commit.html
func (clt *Client) CodeSubmit(authorizerAccessToken, incompleteURL string, templateId int, extJson, userVersion, userDesc string) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/commit?access_token="
	}
	if len(authorizerAccessToken) == 0 || templateId < 0 || len(extJson) == 0 || len(userVersion) == 0 || len(userDesc) == 0 {
		err = errors.New("missing required params")
		return
	}
	var response = new(Error)
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	vals := make(map[string]interface{}, 0)
	vals["template_id"] = templateId
	vals["ext_json"] = extJson
	vals["user_version"] = userVersion
	vals["user_desc"] = userDesc
	valByte, err := json.Marshal(vals)
	logs.Info("beegoBody:%s", string(valByte))
	if err != nil {
		return
	}
	finalURL := incompleteURL + url.QueryEscape(authorizerAccessToken)
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 小程序提交审核
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/code/submit_audit.html
func (clt *Client) SubmitAudit(authorizerAccessToken, incompleteURL string, itemLists []ItemList, feedbackInfo, feedbackStuff string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/submit_audit?access_token="
	}
	if len(authorizerAccessToken) == 0 || len(itemLists) == 0 {
		err = errors.New("missing required params")
		return
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	vals := make(map[string]interface{}, 0)
	vals["item_list"] = itemLists
	if len(feedbackInfo) > 0 {
		vals["feedback_info"] = feedbackInfo
	}
	if len(feedbackStuff) > 0 {
		vals["feedback_stuff"] = feedbackStuff
	}
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + url.QueryEscape(authorizerAccessToken)
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 查询最新一次提交的审核状态
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/code/get_latest_auditstatus.html
func (clt *Client) GetLatestAuditstatus(authorizerAccessToken, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/get_latest_auditstatus?access_token="
	}
	if len(authorizerAccessToken) == 0 {
		err = errors.New("missing required params")
		return
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	finalURL := incompleteURL + url.QueryEscape(authorizerAccessToken)
	if err = httpGetJSON(httpClient, finalURL, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 发布已通过审核的小程序
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/code/release.html
func (clt *Client) WxaRelease(authorizerAccessToken, incompleteURL string) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/release?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	var response = new(Error)
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	finalURL := incompleteURL + authorizerAccessToken
	if err = httpGetJSON(httpClient, finalURL, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 获取体验码
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/code/get_qrcode.html
func (clt *Client) GetQRCode(authorizerAccessToken, path, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/get_qrcode"
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	vals := url.Values{}
	vals.Add("access_token", authorizerAccessToken)
	vals.Add("path", path)
	finalURL := incompleteURL + "?" + vals.Encode()
	if err = httpGet(httpClient, finalURL, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 绑定微信用户为体验者
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/Admin.html
func (clt *Client) BindTester(authorizerAccessToken, wechatId, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/bind_tester?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	vals := make(map[string]interface{}, 0)
	vals["wechatid"] = wechatId
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + authorizerAccessToken
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 解除绑定体验者
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/unbind_tester.html
func (clt *Client) UnbindTester(authorizerAccessToken, wechatId, userstr, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/unbind_tester?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	vals := make(map[string]interface{}, 0)
	vals["wechatid"] = wechatId
	vals["userstr"] = userstr
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + authorizerAccessToken
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 获取审核时可填写的类目信息
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/category/getallcategories.html
func (clt *Client) GetAllCategories(authorizerAccessToken, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/wxopen/getallcategories?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	finalURL := incompleteURL + authorizerAccessToken
	if err = httpGetJSON(httpClient, finalURL, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 获取已设置的所有类目
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/category/getallcategories.html
func (clt *Client) GetConfigedCategory(authorizerAccessToken, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/wxopen/getcategory?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	finalURL := incompleteURL + authorizerAccessToken
	if err = httpGetJSON(httpClient, finalURL, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 获取审核时可填写的类目信息
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/category/get_category.html
func (clt *Client) GetCategory(authorizerAccessToken, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/get_category?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	finalURL := incompleteURL + authorizerAccessToken
	if err = httpGetJSON(httpClient, finalURL, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 添加类目
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/category/addcategory.html
func (clt *Client) AddCategory(authorizerAccessToken string, cats []Cat, incompleteURL string) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/wxopen/addcategory?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	var response = new(Error)
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)

	vals := make(map[string]interface{}, 0)
	vals["categories"] = cats
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + authorizerAccessToken
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 修改类目
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/category/modifycategory.html
func (clt *Client) ModifyCategory(authorizerAccessToken string, cat Cat, incompleteURL string) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/wxopen/modifycategory?access_token?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	var response = new(Error)
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	valByte, err := json.Marshal(cat)
	if err != nil {
		return
	}
	finalURL := incompleteURL + authorizerAccessToken
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 删除类目
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/category/deletecategory.html
func (clt *Client) DelCategory(authorizerAccessToken string, firstCatId, secondCatId int, incompleteURL string) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/wxopen/deletecategory?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	var response = new(Error)
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)

	vals := make(map[string]interface{}, 0)
	vals["first"] = firstCatId
	vals["second"] = secondCatId
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + authorizerAccessToken
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 获取体验者列表
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/memberauth.html
func (clt *Client) GetTesterList(authorizerAccessToken, wechatId, userstr, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/memberauth?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = wechatUtil.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	vals := make(map[string]interface{}, 0)
	vals["wechatid"] = wechatId
	vals["userstr"] = userstr
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + authorizerAccessToken
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}
	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		err = errors.New(ErrorStructValue.Field(errorErrMsgIndex).String())
		return
	default:
		return
	}
}

// 审核事件请求处理
//https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/code/audit_event.html
func (srv *DefaultComponentAccessTokenServer) HandleAuditEventMsg(r *http.Request, query url.Values) (msgPlaintext []byte, mixedMsg core.MixedMsg, err error) {
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
			currentToken, lastToken := srv.getEncodeToken()
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
					srv.removeLastEncodeToken(lastToken)
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
			var encryptedMsgLen int
			encryptedMsgLen, err = base64.StdEncoding.Decode(encryptedMsg, requestHttpBody.Base64EncryptedMsg)
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
			var (
				haveAppIdBytes []byte
			)
			_, msgPlaintext, haveAppIdBytes, err = util.AESDecryptMsg(encryptedMsg, aesKey)
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
			mixedMsg = core.MixedMsg{}
			if err = xml.Unmarshal(msgPlaintext, &mixedMsg); err != nil {
				return
			}
			if haveToUserName != mixedMsg.ToUserName {
				err = fmt.Errorf("the message ToUserName mismatch between ciphertext and plaintext, %q != %q",
					haveToUserName, mixedMsg.ToUserName)
				return
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
			currentToken, lastToken := srv.getEncodeToken()
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
					srv.removeLastEncodeToken(lastToken)
				}
			}
			msgPlaintext, err = ioutil.ReadAll(r.Body)
			if err != nil {
				return
			}
			callback.DebugPrintPlainRequestMessage(msgPlaintext)
			mixedMsg = core.MixedMsg{}
			if err = xml.Unmarshal(msgPlaintext, &mixedMsg); err != nil {
				return
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
		currentToken, lastToken := srv.getEncodeToken()
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
				srv.removeLastEncodeToken(lastToken)
			}
		}
		return
	}
	return
}
