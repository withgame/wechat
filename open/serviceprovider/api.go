/*
 * Copyright (c) 2019. 深圳青木文化传播有限公司.
 */

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
}

// 获取授权方的帐号基本信息,GetAuthorizerAccessToken 返回 authorizerAccessToken
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/Mini_Program_Information_Settings.html
func (clt *Client) GetAccountBasicInfo(authorizerAccessToken, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/account/getaccountbasicinfo?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
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

// 生成第三方服务商授权链接
// 授权流程完成后，授权页会自动跳转进入回调 URI，并在 URL 参数中返回授权码和过期时间(redirect_url?auth_code=xxx&expires_in=600)
func (clt *Client) GetAuthUrlForWeb(redirectUrl, bizAppId string, authType AuthType) (authUrl string, err error) {
	if len(redirectUrl) == 0 {
		err = errors.New("missing redirectUrl")
		return
	}
	//token, err := clt.Token()
	//ticket, err := clt.AccessTokenServer.Ticket()
	preAuthCode, err := clt.AccessTokenServer.PreAuthCode()
	if err != nil {
		return
	}
	//redirectUri, err := url.Parse(redirectUrl)
	redirectUri, err := url.Parse(redirectUrl)
	if err != nil {
		return
	}
	queryStr := ""
	fragmentStr := ""
	if len(redirectUri.Fragment) > 0 {
		fragmentStr = fmt.Sprintf("#%s", redirectUri.Fragment)
	}
	if len(redirectUri.Query()) > 0 {
		queryStr = fmt.Sprintf("?%s%s", redirectUri.Query().Encode(), fragmentStr)
	} else {
		queryStr = fragmentStr
	}
	redirectUrl = fmt.Sprintf("%s://%s%s%s", redirectUri.Scheme, redirectUri.Host, redirectUri.Path, queryStr)

	//redirectUri, err = url.QueryUnescape(redirectUri)
	//if err != nil {
	//	return
	//}
	//redirectUri = url.QueryEscape(redirectUri)
	//https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=xxxx&pre_auth_code=xxxxx&redirect_uri=xxxx&auth_type=xxx
	incompleteURL := "https://mp.weixin.qq.com/cgi-bin/componentloginpage?"
	vals := url.Values{}
	vals.Add("component_appid", clt.AccessTokenServer.appId)
	vals.Add("pre_auth_code", preAuthCode)
	//vals.Add("redirect_uri", redirectUrl)
	if authType != AuthTypeNil {
		vals.Add("auth_type", fmt.Sprintf("%d", authType))
	}
	if len(bizAppId) > 0 {
		vals.Add("biz_appid", bizAppId)
	}
	authUrl = incompleteURL + vals.Encode() + "&redirect_uri=" + redirectUrl
	return
}

// 点击移动端链接快速授权 第三方平台方可以生成授权链接，将链接通过移动端直接发给授权管理员，管理员确认后即授权成功。
// 授权流程完成后，授权页会自动跳转进入回调 URI，并在 URL 参数中返回授权码和过期时间(redirect_url?auth_code=xxx&expires_in=600)
func (clt *Client) GetAuthUrlForMobile(redirectUrl, bizAppId string, authType AuthType) (authUrl string, err error) {
	if len(redirectUrl) == 0 {
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
	//redirectUri, err = url.QueryUnescape(redirectUri)
	//if err != nil {
	//	return
	//}
	//redirectUri = url.QueryEscape(redirectUri)

	redirectUri, err := url.Parse(redirectUrl)
	if err != nil {
		return
	}
	queryStr := ""
	fragmentStr := ""
	if len(redirectUri.Fragment) > 0 {
		fragmentStr = fmt.Sprintf("#%s", redirectUri.Fragment)
	}
	if len(redirectUri.Query()) > 0 {
		queryStr = fmt.Sprintf("?%s%s", redirectUri.Query().Encode(), fragmentStr)
	} else {
		queryStr = fragmentStr
	}
	redirectUrl = fmt.Sprintf("%s://%s%s%s", redirectUri.Scheme, redirectUri.Host, redirectUri.Path, queryStr)
	//https://mp.weixin.qq.com/safe/bindcomponent?action=bindcomponent&auth_type=3&no_scan=1&component_appid=xxxx&pre_auth_code=xxxxx&redirect_uri=xxxx&auth_type=xxx&biz_appid=xxxx#wechat_redirect
	incompleteURL := "https://mp.weixin.qq.com/safe/bindcomponent?"
	vals := url.Values{}
	vals.Add("action", "bindcomponent")
	vals.Add("component_appid", clt.AccessTokenServer.appId)
	vals.Add("pre_auth_code", preAuthCode)
	//vals.Add("redirect_uri", redirectUrl)
	vals.Add("auth_type", fmt.Sprintf("%d", authType))
	if len(bizAppId) > 0 {
		vals.Add("biz_appid", bizAppId)
	}
	authUrl = incompleteURL + vals.Encode() + "&redirect_uri=" + redirectUrl + "#wechat_redirect"
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
	//vals["component_access_token"] = token
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
	//vals["component_access_token"] = token
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

// 小程序登录
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/WeChat_login.html
func (clt *Client) WxLogin(bizAppId, jsCode, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/sns/component/jscode2session"
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	token, err := clt.Token()
	if err != nil {
		return
	}
	vals := url.Values{}
	vals.Add("appid", bizAppId)
	vals.Add("js_code", jsCode)
	vals.Add("grant_type", "authorization_code")
	vals.Add("component_appid", clt.AccessTokenServer.appId)
	vals.Add("component_access_token", token)
	finalURL := incompleteURL + "?" + vals.Encode()
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

// 获取消息模板标题列表
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/message_template/library_list.html
func (clt *Client) GetMsgTplList(offset, limit int, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/wxopen/template/library/list?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	token, err := clt.Token()
	if err != nil {
		return
	}
	vals := make(map[string]interface{}, 0)
	vals["offset"] = offset
	vals["count"] = limit
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + token
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

// 获取消息模板标题下的关键词库
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/message_template/library_get.html
func (clt *Client) GetMsgTplKeywords(tplId, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/wxopen/template/library/list?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	token, err := clt.Token()
	if err != nil {
		return
	}
	vals := make(map[string]interface{}, 0)
	vals["id"] = tplId
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + token
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

// 组合消息模板并添加到个人模板库
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/message_template/add_template.html
func (clt *Client) AddMsgTplIntoAccount(tplId string, keywordIds []int, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/wxopen/template/add?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	token, err := clt.Token()
	if err != nil {
		return
	}
	vals := make(map[string]interface{}, 0)
	vals["id"] = tplId
	vals["keyword_id_list"] = keywordIds
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + token
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

// 获取帐号下的消息模板列表
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/message_template/list_template.html
func (clt *Client) GetAccountMsgTpls(offset, limit int, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/wxopen/template/list?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	token, err := clt.Token()
	if err != nil {
		return
	}
	vals := make(map[string]interface{}, 0)
	vals["offset"] = offset
	vals["count"] = limit
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + token
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

// 删除帐号下的某个模板
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/message_template/list_template.html
func (clt *Client) DelAccountMsgTpl(tplId string, incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/cgi-bin/wxopen/template/del?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	token, err := clt.Token()
	if err != nil {
		return
	}
	vals := make(map[string]interface{}, 0)
	vals["template_id"] = tplId
	valByte, err := json.Marshal(vals)
	if err != nil {
		return
	}
	finalURL := incompleteURL + token
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

// 获取代码模板列表
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Mini_Programs/code_template/gettemplatelist.html
func (clt *Client) GetTemplateList(incompleteURL string, response interface{}) (err error) {
	if len(incompleteURL) == 0 {
		incompleteURL = "https://api.weixin.qq.com/wxa/gettemplatelist?access_token="
	}
	httpClient := clt.HttpClient
	if httpClient == nil {
		httpClient = util.DefaultHttpClient
	}
	ErrorStructValue, ErrorErrCodeValue := checkResponse(response)
	token, err := clt.Token()
	if err != nil {
		return
	}
	finalURL := incompleteURL + token
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
