# 请求URL

> http://localhost:5556/dex/auth/ginapi?client_id=my-app&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcallback&response_type=code&scope=openid+email+profile&state=random-state

# 账号密码

admin/admin123

# dex run

> ./config serve examples/ginapi/config.ginapi.yaml

# ginapi run

> go run main.go