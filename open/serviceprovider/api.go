package serviceprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/chanxuehong/wechat/internal/debug/api/retry"
	"github.com/chanxuehong/wechat/util"
	"net/url"
)

type (
	AuthType   int
	ActionType string
)

// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Authorization_Process_Technical_Description.html
const (
	AuthTypeNil        AuthType = 0
	AuthTypePhoneScan  AuthType = 1
	AuthTypeOnlyMiniMP AuthType = 2
	AuthTypeBoth       AuthType = 3
)

const (
	ActionTypeNil ActionType = ""
	ActionTypeAdd ActionType = "add"
	ActionTypeDel ActionType = "delete"
	ActionTypeSet ActionType = "set"
	ActionTypeGet ActionType = "get"
)

// 获取授权方的帐号基本信息
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/api/api_get_authorizer_info.html
func (clt *Client) GetAuthorizerAppInfo(bizAppId, incompleteURL string, response interface{}) (err error) {
	if len(bizAppId) == 0 {
		err = errors.New("missing bizAppId")
		return
	}
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_info?component_access_token="
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}

	token, err := clt.Token()
	if err != nil {
		return
	}
	vals := make(map[string]string, 0)
	vals["component_appid"] = clt.AccessTokenServer.appId
	vals["authorizer_appid"] = bizAppId
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	hasRetried := false
RETRY:
	finalURL := incompleteURL + url.QueryEscape(token)
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}

	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		errMsg := ErrorStructValue.Field(errorErrMsgIndex).String()
		retry.DebugPrintError(errCode, errMsg, token)
		if !hasRetried {
			hasRetried = true
			ErrorStructValue.Set(errorZeroValue)
			if token, err = clt.RefreshToken(token); err != nil {
				return
			}
			retry.DebugPrintNewToken(token)
			goto RETRY
		}
		retry.DebugPrintFallthrough(token)
		fallthrough
	default:
		return
	}
	return
}

// 生成第三方服务商授权链接
// 授权流程完成后，授权页会自动跳转进入回调 URI，并在 URL 参数中返回授权码和过期时间(redirect_url?auth_code=xxx&expires_in=600)
func (clt *Client) GetAuthUrlForWeb(redirectUri, bizAppId string, authType AuthType) (authUrl string, err error) {
	if len(redirectUri) == 0 {
		err = errors.New("missing redirectUri")
		return
	}
	preAuthCode, err := clt.AccessTokenServer.PreAuthCode()
	if err != nil {
		return
	}
	redirectUri, err = url.QueryUnescape(redirectUri)
	if err != nil {
		return
	}
	redirectUri = url.QueryEscape(redirectUri)
	//https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=xxxx&pre_auth_code=xxxxx&redirect_uri=xxxx&auth_type=xxx
	incompleteURL := "https://mp.weixin.qq.com/cgi-bin/componentloginpage?"
	vals := url.Values{}
	vals.Add("component_appid", clt.AccessTokenServer.appId)
	vals.Add("pre_auth_code", preAuthCode)
	vals.Add("redirect_uri", redirectUri)
	if authType != AuthTypeNil {
		vals.Add("auth_type", fmt.Sprintf("%d", authType))
	}
	if len(bizAppId) > 0 {
		vals.Add("biz_appid", bizAppId)
	}
	authUrl = incompleteURL + vals.Encode()
	return
}

// 点击移动端链接快速授权 第三方平台方可以生成授权链接，将链接通过移动端直接发给授权管理员，管理员确认后即授权成功。
// 授权流程完成后，授权页会自动跳转进入回调 URI，并在 URL 参数中返回授权码和过期时间(redirect_url?auth_code=xxx&expires_in=600)
func (clt *Client) GetAuthUrlForMobile(redirectUri, bizAppId string, authType AuthType) (authUrl string, err error) {
	if len(redirectUri) == 0 {
		err = errors.New("missing redirectUri")
		return
	}
	if authType == AuthTypeNil {
		err = errors.New("missing authType")
		return
	}
	preAuthCode, err := clt.AccessTokenServer.PreAuthCode()
	if err != nil {
		return
	}
	redirectUri, err = url.QueryUnescape(redirectUri)
	if err != nil {
		return
	}
	redirectUri = url.QueryEscape(redirectUri)
	//https://mp.weixin.qq.com/safe/bindcomponent?action=bindcomponent&auth_type=3&no_scan=1&component_appid=xxxx&pre_auth_code=xxxxx&redirect_uri=xxxx&auth_type=xxx&biz_appid=xxxx#wechat_redirect
	incompleteURL := "https://mp.weixin.qq.com/safe/bindcomponent?"
	vals := url.Values{}
	vals.Add("action", "bindcomponent")
	vals.Add("component_appid", clt.AccessTokenServer.appId)
	vals.Add("pre_auth_code", preAuthCode)
	vals.Add("redirect_uri", redirectUri)
	vals.Add("auth_type", fmt.Sprintf("%d", authType))
	if len(bizAppId) > 0 {
		vals.Add("biz_appid", bizAppId)
	}
	authUrl = incompleteURL + vals.Encode() + "#wechat_redirect"
	return
}

// 使用授权码获取授权信息
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/api/authorization_info.html
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/api/authorize_event.html
func (clt *Client) GetAuthorizerAccessToken(AuthorizationCode, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token="
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}

	token, err := clt.Token()
	if err != nil {
		return
	}

	vals := make(map[string]string, 0)
	vals["component_access_token"] = token
	vals["component_appid"] = clt.AccessTokenServer.appId
	vals["authorization_code"] = AuthorizationCode
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	hasRetried := false
RETRY:
	finalURL := incompleteURL + url.QueryEscape(token)
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}

	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		errMsg := ErrorStructValue.Field(errorErrMsgIndex).String()
		retry.DebugPrintError(errCode, errMsg, token)
		if !hasRetried {
			hasRetried = true
			ErrorStructValue.Set(errorZeroValue)
			if token, err = clt.RefreshToken(token); err != nil {
				return
			}
			retry.DebugPrintNewToken(token)
			goto RETRY
		}
		retry.DebugPrintFallthrough(token)
		fallthrough
	default:
		return
	}
}

// 获取/刷新接口调用令牌
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/api/api_authorizer_token.html
func (clt *Client) RefreshAuthorizerAccessToken(bizAppId, authorizerRefreshToken, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/component/api_authorizer_token?component_access_token="
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}
	token, err := clt.Token()
	if err != nil {
		return
	}

	vals := make(map[string]string, 0)
	vals["component_access_token"] = token
	vals["component_appid"] = clt.AccessTokenServer.appId
	vals["authorizer_appid"] = bizAppId
	vals["authorizer_refresh_token"] = authorizerRefreshToken
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}

	hasRetried := false
RETRY:
	finalURL := incompleteURL + url.QueryEscape(token)
	if err = httpPostJSON(httpClient, finalURL, valByte, response); err != nil {
		return
	}

	switch errCode := ErrorErrCodeValue.Int(); errCode {
	case ErrCodeOK:
		return
	case ErrCodeInvalidCredential, ErrCodeAccessTokenExpired:
		errMsg := ErrorStructValue.Field(errorErrMsgIndex).String()
		retry.DebugPrintError(errCode, errMsg, token)
		if !hasRetried {
			hasRetried = true
			ErrorStructValue.Set(errorZeroValue)
			if token, err = clt.RefreshToken(token); err != nil {
				return
			}
			retry.DebugPrintNewToken(token)
			goto RETRY
		}
		retry.DebugPrintFallthrough(token)
		fallthrough
	default:
		return
	}
}

// 设置服务器域名
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/Server_Address_Configuration.html
func (clt *Client) ModifyDomain(authorizerAccessToken, incompleteURL string, action ActionType, domains map[string][]string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/modify_domain?access_token="
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}
	if len(domains["req"]) == 0 || len(domains["ws"]) == 0 || len(domains["upload"]) == 0 || len(domains["download"]) == 0 {
		err = errors.New("missing required params")
		return
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
