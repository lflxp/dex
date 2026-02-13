package ginapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dexidp/dex/connector"
)

// NewConnector 初始化自定义Connector（Dex会调用此方法）
func NewConnector(ctx context.Context, logger *slog.Logger, config Config) (connector.Connector, error) {
	// 校验配置必填项
	if config.APIURL == "" {
		return nil, errors.New("apiURL is required")
	}
	if config.ClientID == "" {
		return nil, errors.New("clientID is required")
	}
	if config.LoginPath == "" {
		config.LoginPath = "/auth/login" // 默认登录路径
	}
	if config.CallbackPath == "" {
		config.CallbackPath = "/auth/callback" // 默认回调路径
	}

	return &Connector{
		config:             config,
		logger:             logger,
		APIURL:             strings.TrimSuffix(config.APIURL, "/"),
		ClientID:           config.ClientID,
		ClientSecret:       config.ClientSecret,
		LoginPath:          config.LoginPath,
		CallbackPath:       config.CallbackPath,
		InsecureSkipVerify: config.InsecureSkipVerify,
	}, nil
}

// Open 实现Connector接口：初始化连接器实例
func (c *Connector) Open(id string, logger *slog.Logger) (connector.Connector, error) {
	return &Connector{
		config:       c.config,
		logger:       logger.With(slog.String("connector", "ginapi")),
		APIURL:       c.APIURL,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		LoginPath:    c.LoginPath,
		CallbackPath: c.CallbackPath,
	}, nil
}

// LoginURL 实现Connector接口：生成跳转到Gin API登录页的URL
func (c *Connector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	// 1. 解析Gin API的登录基础URL（确保路径正确）
	c.logger.With("Connector", c).Info("Connector is")
	loginBaseURL := fmt.Sprintf("%s%s", c.APIURL, c.LoginPath)
	loginURL, err := url.Parse(loginBaseURL)
	if err != nil {
		return "", fmt.Errorf("parse login URL failed: %v", err)
	}

	// 2. 构造查询参数（强制URL编码，避免特殊字符导致参数丢失）
	params := url.Values{}
	params.Add("client_id", c.ClientID)
	// 关键：对回调地址进行URL编码（Dex传递的callbackURL已经是编码后的，但二次传递需确保正确）
	params.Add("redirect_uri", url.QueryEscape(callbackURL))
	params.Add("state", url.QueryEscape(state)) // 对state也编码，防止特殊字符

	loginURL.RawQuery = params.Encode()
	c.logger.With("URL", loginURL.String()).Info("Generated Gin API login URL")
	return loginURL.String(), nil
}

// HandleCallback 实现Connector接口：处理Gin API的回调，校验用户身份和权限
func (c *Connector) HandleCallback(s connector.Scopes, r *http.Request) (connector.Identity, error) {
	// 1. 从回调请求中获取code和state（Gin API返回）
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		return connector.Identity{}, errors.New("missing code or state in callback")
	}

	// 2. 调用Gin API的校验接口，换取用户信息
	verifyURL := c.APIURL + "/auth/verify"
	params := url.Values{}
	params.Add("code", code)
	params.Add("client_id", c.ClientID)
	params.Add("client_secret", c.ClientSecret)
	params.Add("state", state)

	// 3. 发送POST请求到Gin API校验授权码
	req, err := http.NewRequest("POST", verifyURL, strings.NewReader(params.Encode()))
	if err != nil {
		return connector.Identity{}, fmt.Errorf("create verify request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("call verify API failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return connector.Identity{}, fmt.Errorf("verify API returned non-200 status: %d", resp.StatusCode)
	}

	// 4. 解析Gin API返回的用户信息
	var identityResp IdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&identityResp); err != nil {
		return connector.Identity{}, fmt.Errorf("decode identity response failed: %v", err)
	}

	// 5. 校验用户信息必填项
	if identityResp.UserID == "" {
		return connector.Identity{}, errors.New("userID is required in identity response")
	}
	if identityResp.Username == "" {
		return connector.Identity{}, errors.New("username is required in identity response")
	}

	// --- 关键修复1：序列化自定义数据到ConnectorData（[]byte） ---
	customData := CustomConnectorData{
		AccessToken: identityResp.AccessToken,
		Expiry:      time.Now().Add(time.Duration(identityResp.ExpiresIn) * time.Second),
	}
	// 将自定义数据序列化为JSON字节数组
	connectorDataBytes, err := json.Marshal(customData)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("marshal custom connector data failed: %v", err)
	}

	// 5. 构造Dex的Identity对象
	identity := connector.Identity{
		UserID:        identityResp.UserID,
		Username:      identityResp.Username,
		Email:         identityResp.Email,
		EmailVerified: identityResp.EmailVerified,
		Groups:        identityResp.Groups,
		ConnectorData: connectorDataBytes, // 存入序列化后的字节数组
	}

	return identity, nil
}

// Refresh 实现Connector接口：刷新用户身份（可选，按需实现）
func (c *Connector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	// --- 关键修复2：反序列化ConnectorData获取AccessToken和Expiry ---
	// 先反序列化自定义数据
	var customData CustomConnectorData
	if len(identity.ConnectorData) > 0 {
		if err := json.Unmarshal(identity.ConnectorData, &customData); err != nil {
			return connector.Identity{}, fmt.Errorf("unmarshal connector data failed: %v", err)
		}
	}

	// 1. 检查令牌是否过期
	if customData.Expiry.After(time.Now()) {
		return identity, nil
	}

	// 2. 调用Gin API的刷新接口
	refreshURL := c.APIURL + "/auth/refresh"
	params := url.Values{}
	params.Add("client_id", c.ClientID)
	params.Add("client_secret", c.ClientSecret)
	params.Add("refresh_token", customData.AccessToken) // 使用反序列化后的AccessToken

	req, err := http.NewRequest("POST", refreshURL, strings.NewReader(params.Encode()))
	if err != nil {
		return connector.Identity{}, fmt.Errorf("create refresh request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("call refresh API failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return connector.Identity{}, fmt.Errorf("refresh API returned non-200 status: %d", resp.StatusCode)
	}

	// 3. 解析刷新后的用户信息
	var refreshResp IdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&refreshResp); err != nil {
		return connector.Identity{}, fmt.Errorf("decode refresh response failed: %v", err)
	}

	// 4. 更新自定义数据并重新序列化
	updatedCustomData := CustomConnectorData{
		AccessToken: refreshResp.AccessToken,
		Expiry:      time.Now().Add(time.Duration(refreshResp.ExpiresIn) * time.Second),
	}
	updatedConnectorDataBytes, err := json.Marshal(updatedCustomData)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("marshal updated connector data failed: %v", err)
	}

	// 5. 更新Identity对象
	identity.UserID = refreshResp.UserID
	identity.Username = refreshResp.Username
	identity.Email = refreshResp.Email
	identity.EmailVerified = refreshResp.EmailVerified
	identity.Groups = refreshResp.Groups
	identity.ConnectorData = updatedConnectorDataBytes // 替换为新的序列化字节数组

	return identity, nil
}

// Close 实现Connector接口：关闭连接器（无资源需释放，空实现）
func (c *Connector) Close() error {
	return nil
}

// RegisterConnector 注册自定义Connector到Dex（Dex启动时会加载）
