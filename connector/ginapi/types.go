package ginapi

import (
	"log/slog"
	"time"
)

// Config 自定义Connector的配置结构（对应Dex配置文件）
type Config struct {
	// Gin API的基础地址
	APIURL string `json:"apiURL"`
	// 对接Gin API的客户端ID（用于鉴权）
	ClientID string `json:"clientID"`
	// 对接Gin API的客户端秘钥
	ClientSecret string `json:"clientSecret"`
	// 登录页面的路径（Gin API提供的登录页）
	LoginPath string `json:"loginPath"`
	// 回调路径（Gin API处理完登录后跳转回Dex的路径）
	CallbackPath       string `json:"callbackPath"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

// Connector 实现Dex的Connector接口
type Connector struct {
	config Config
	logger *slog.Logger
	// Gin API的基础地址
	APIURL string `json:"apiURL"`
	// 对接Gin API的客户端ID（用于鉴权）
	ClientID string `json:"clientID"`
	// 对接Gin API的客户端秘钥
	ClientSecret string `json:"clientSecret"`
	// 登录页面的路径（Gin API提供的登录页）
	LoginPath string `json:"loginPath"`
	// 回调路径（Gin API处理完登录后跳转回Dex的路径）
	CallbackPath       string `json:"callbackPath"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

// IdentityResponse Gin API返回的用户身份信息结构
type IdentityResponse struct {
	// 用户唯一ID（必填）
	UserID string `json:"userId"`
	// 用户名（必填）
	Username string `json:"username"`
	// 邮箱（可选）
	Email string `json:"email"`
	// 邮箱是否验证（可选）
	EmailVerified bool `json:"emailVerified"`
	// 权限/角色（可选，会注入到OAuth2令牌的claims中）
	Groups []string `json:"groups"`
	Tenant string   `json:"tenant"`
	// 访问令牌（可选，用于后续刷新）
	AccessToken string `json:"accessToken"`
	// 令牌过期时间（秒）
	ExpiresIn int64 `json:"expiresIn"`
}

// CallbackRequest Gin API回调时传递的参数结构
type CallbackRequest struct {
	// 登录态（防CSRF）
	State string `json:"state"`
	// 授权码（Gin API生成）
	Code string `json:"code"`
}

// --- 新增：自定义Connector数据结构体（用于序列化） ---
type CustomConnectorData struct {
	AccessToken string    `json:"accessToken"`
	Expiry      time.Time `json:"expiry"`
}
