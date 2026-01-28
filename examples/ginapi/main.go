// gin-api/main.go
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

// 模拟用户数据
var users = map[string]string{
	"admin": "admin123",
	"user":  "user123",
}

// 模拟授权码存储（生产环境需用Redis/数据库）
var authCodes = map[string]AuthCodeInfo{}

// AuthCodeInfo 授权码信息
type AuthCodeInfo struct {
	UserID    string
	Username  string
	Email     string
	Groups    []string
	Tenant    string
	ExpiresAt time.Time
}

func main() {
	r := gin.Default()

	r.GET("/callback", func(c *gin.Context) {
		slog.With("header", c.Request.Header).Info("callback")
		c.String(200, "success")
	})
	// 1. 登录页面（GET）
	// 在gin-api/main.go的/auth/login GET接口中替换为HTML响应（更贴近真实场景）
	r.GET("/auth/login", func(c *gin.Context) {
		clientID := c.Query("client_id")
		redirectURI := c.Query("redirect_uri")
		// 解码Dex传递的redirect_uri（因为之前编码过）
		decodedRedirectURI, _ := url.QueryUnescape(redirectURI)
		state := c.Query("state")
		decodedState, _ := url.QueryUnescape(state)

		// 渲染简单的登录表单（替代JSON响应，避免前端无交互）
		html := fmt.Sprintf(`
		<html>
		<body>
			<h1>Login to Gin API Auth</h1>
			<form method="POST" action="/auth/login">
				<input type="hidden" name="client_id" value="%s">
				<input type="hidden" name="redirect_uri" value="%s">
				<input type="hidden" name="state" value="%s">
				<div>
					<label>Username:</label>
					<input type="text" name="username" required>
				</div>
				<div>
					<label>Password:</label>
					<input type="password" name="password" required>
				</div>
				<button type="submit">Login</button>
			</form>
		</body>
		</html>
	`, clientID, decodedRedirectURI, decodedState)

		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, html)
	})

	// 2. 登录提交（POST）：验证用户名密码，生成授权码
	r.POST("/auth/login", func(c *gin.Context) {
		slog.Info("auth/login")

		// 定义结构体，同时支持 form 和 json 标签
		var req struct {
			Username    string `form:"username" json:"username"`
			Password    string `form:"password" json:"password"`
			ClientID    string `form:"client_id" json:"client_id"`
			RedirectURI string `form:"redirect_uri" json:"redirect_uri"`
			State       string `form:"state" json:"state"`
		}

		// 使用 ShouldBind 方法，它能自动识别内容类型并绑定数据
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 校验用户名密码
		if _, ok := users[req.Username]; !ok || users[req.Username] != req.Password {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
			return
		}

		// 生成授权码（生产环境需用安全的随机数）
		code := generateRandomCode()
		// 存储授权码信息（有效期5分钟）
		authCodes[code] = AuthCodeInfo{
			UserID:    "user-" + req.Username,
			Username:  req.Username,
			Email:     req.Username + "@example.com",
			Groups:    []string{"group:" + req.Username}, // 模拟权限组
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}

		// 跳转回Dex的回调地址，携带code和state
		redirectURL, err := url.Parse(req.RedirectURI)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的重定向URL"})
			return
		}
		params := url.Values{}
		params.Add("code", code)
		params.Add("state", req.State)
		redirectURL.RawQuery = params.Encode()

		c.Redirect(http.StatusFound, redirectURL.String())
	})

	// 3. 校验授权码（POST）：Dex回调后调用此接口获取用户信息
	r.POST("/auth/verify", func(c *gin.Context) {
		slog.Info("/auth/verify")
		code := c.PostForm("code")
		clientID := c.PostForm("client_id")
		clientSecret := c.PostForm("client_secret")

		// 校验客户端凭证（生产环境需严格校验）
		if clientID != "dex-client-123" || clientSecret != "dex-secret-456" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "客户端凭证无效"})
			return
		}

		// 校验授权码
		codeInfo, ok := authCodes[code]
		if !ok || codeInfo.ExpiresAt.Before(time.Now()) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "授权码无效或已过期"})
			return
		}

		// 返回用户身份信息（Dex需要的格式）
		c.JSON(http.StatusOK, gin.H{
			"userId":        codeInfo.UserID,
			"username":      codeInfo.Username,
			"email":         codeInfo.Email,
			"emailVerified": true,
			"groups":        codeInfo.Groups,
			"accessToken":   generateRandomCode(), // 模拟access_token
			"expiresIn":     3600,                 // 1小时过期
		})

		// 一次性使用，删除授权码
		delete(authCodes, code)
	})

	// 4. 刷新令牌（POST）：可选
	r.POST("/auth/refresh", func(c *gin.Context) {
		slog.Info("/auth/refresh")
		refreshToken := c.PostForm("refresh_token")
		// 模拟刷新逻辑（生产环境需校验refresh_token）
		c.JSON(http.StatusOK, gin.H{
			"userId":        "user-admin",
			"username":      "admin",
			"email":         "admin@example.com",
			"emailVerified": true,
			"groups":        []string{"group:admin"},
			"accessToken":   generateRandomCode(),
			"refreshToken":  refreshToken,
			"expiresIn":     3600,
		})
	})

	// 启动Gin API
	r.Run(":8089")
}

// 生成随机授权码（生产环境需用更安全的方式）
func generateRandomCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
