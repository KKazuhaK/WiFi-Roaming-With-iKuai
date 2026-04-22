# Kazuha Hub Roaming

统一的团队 WiFi 接入方案：多个物理地点共享同一 SSID `Kazuha Hub Roaming`，
成员用 Entra ID 账号 (MFA 强制) 登录一次即可上网，Guest 账号自动拒绝。

架构、设计决策、Phase 进度见 [`project-notes.md`](./project-notes.md)。
这份 README 只讲 **怎么把 Portal 跑起来**。

---

## 目录

```
WiFi-Roaming-With-iKuai/
├── README.md                  # 本文
├── project-notes.md           # 设计决策 / Phase 进度
├── portal/                    # Go 源码 + Dockerfile + 前端模板
│   ├── main.go                # HTTP 路由
│   ├── config.go              # 环境变量读取
│   ├── session.go             # HMAC 签名 cookie
│   ├── oidc.go                # Entra OIDC 流程
│   ├── ikuai.go               # iKuai 放行 token 生成
│   ├── i18n.go                # 中英双语字符串
│   ├── templates/             # 登录页 / 错误页 HTML
│   ├── static/                # logo 等静态资源
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── .env.example           # 环境变量模板, 不含真值
│   └── go.mod
└── deploy/
    ├── docker-compose.yml     # VPS 上跑的是这个
    └── aapanel-nginx-snippet.conf  # 如需手工调 Nginx 的参考
```

---

## Phase 3 · VPS 部署

前置: Phase 1 (Entra App Registration) + Phase 2 (DNS + aaPanel 反代 + SSL)
已全部完成, `curl -I https://wifi.login.example.com` 返回 502。

### 步骤 1: 源码上 VPS

在 VPS 上:

```bash
sudo mkdir -p /opt/wifi-portal
sudo chown $USER:$USER /opt/wifi-portal
cd /opt/wifi-portal
```

把本仓库 (`WiFi-Roaming-With-iKuai/`) 里的这些传上去:

- `portal/` 整个目录
- `deploy/docker-compose.yml` → 放到 `/opt/wifi-portal/docker-compose.yml`
- `portal/.env.example` → 拷贝一份到 `/opt/wifi-portal/.env`

用 `git clone` 或 `scp -r` 都行. 最终目录:

```
/opt/wifi-portal/
├── docker-compose.yml
├── .env                 <- 你刚拷的, 马上要填
└── portal/
    ├── Dockerfile
    ├── main.go
    └── ...
```

### 步骤 2: 填 .env

```bash
cd /opt/wifi-portal
cp portal/.env.example .env
chmod 600 .env         # 只允许你自己读
vim .env               # 或 nano
```

要填的值:

| 变量 | 来源 |
|---|---|
| `TENANT_ID` | `00000000-0000-0000-0000-000000000000` |
| `CLIENT_ID` | `00000000-0000-0000-0000-000000000000` |
| `CLIENT_SECRET` | 你本地密码管理器里 `portal-prod-2026-v2` 的 Value |
| `IKUAI_APPKEY` | Phase 4 做 iKuai 配置时才会有, 先填占位 `PLACEHOLDER` |
| `PUBLIC_URL` | `https://wifi.login.example.com` |
| `SESSION_SECRET` | 运行 `openssl rand -hex 32` 生成一次, 贴进来 |
| `BRAND_NAME` | `Kazuha Hub` 或你喜欢的 |
| `BRAND_COLOR` | 默认 `#2563eb`, 可改 |
| `BRAND_LOGO_URL` | 留空显示首字母, 有 logo 则填 URL |

> ⚠️ `IKUAI_APPKEY` 先占位是为了让 Portal 能起来做 Entra 流程验证. Phase 4 配完
> iKuai 再换成真实 appkey 并 `docker compose restart portal`。

### 步骤 3: 起服务

```bash
cd /opt/wifi-portal
docker compose up -d --build
docker compose logs -f portal
```

预期日志:

```
Portal 启动, 监听 0.0.0.0:28080, public URL: https://wifi.login.example.com
```

### 步骤 4: 端到端自测 (Phase 4 之前)

```bash
# 1. 健康检查
curl https://wifi.login.example.com/healthz
# 预期: ok

# 2. /portal 不带参数直接访问 (模拟有人直接敲域名, 不是从 iKuai 跳过来)
curl -I https://wifi.login.example.com/portal
# 预期: HTTP/2 400 (返回 "session lost" 页)
# 这是正常的. 说明 Portal 认得路由, 但拒绝了非 iKuai 来源的访问.

# 3. /portal 带伪造的 user_ip + mac 参数
curl -I "https://wifi.login.example.com/portal?user_ip=192.168.1.100&mac=aa:bb:cc:dd:ee:ff"
# 预期: HTTP/2 200, Set-Cookie: kz_wifi_sess=...

# 4. 浏览器打开上面第 3 条的 URL, 应该看到登录页.
#    点 "Sign in with Microsoft", 走完 Entra 登录.
#    Entra 回跳后会报错 (iKuai 放行失败因为 appkey 是假的), 但这一步能到
#    说明 Entra OIDC 端到端都通了.
```

---

## Phase 4 · iKuai 接入

详见 `project-notes.md` 里 Phase 4 的步骤. 核心是:

1. iKuai 云控制台 → 自定义认证 → 生成 appkey
2. 替换 VPS `/opt/wifi-portal/.env` 里的 `IKUAI_APPKEY`
3. `docker compose restart portal`
4. iKuai 路由器后台配 SSID `Kazuha Hub Roaming`, 认证对接 URL 填 `https://wifi.login.example.com/portal`
5. 免认证白名单加上 Entra 域名 (见下)

### iKuai 免认证白名单 (必须)

Captive Portal 启动后, 浏览器必须能**先**访问这些域名才能走完登录流程。
把它们全部加到 iKuai 的 "免认证 IP / 免认证域名":

```
login.microsoftonline.com
login.microsoft.com
login.live.com
aadcdn.msftauth.net
aadcdn.msauth.net
graph.microsoft.com
wifi.login.example.com
portal.ikuai8-wifi.com
```

---

## 常用运维命令

```bash
# 查日志
docker compose logs -f portal

# 改了 .env 后生效
docker compose restart portal

# 改了代码后 rebuild
docker compose up -d --build

# 停掉
docker compose down

# 看资源占用
docker stats wifi-portal

# 进容器看文件系统
docker compose exec portal sh
```

---

## 故障排查

### `502 Bad Gateway` (Portal 起了但 Nginx 报 502)

- 容器是不是起来了: `docker compose ps`
- 端口绑对了没: `ss -tlnp | grep 28080` 应该看到 docker-proxy 在听
- 容器内部能通吗: `docker compose exec portal wget -O- http://127.0.0.1:28080/healthz`

### `id_token 验证失败`

- `.env` 的 `TENANT_ID` 和 `CLIENT_ID` 对不对
- 系统时间有没有漂移太多: `timedatectl`
- Entra 是不是改过 App Registration 配置

### `session lost` (用户反复报这个)

- iKuai 传过来的 query 字段名可能不是 `user_ip/user_mac`
- 看日志里 `GET /portal` 那一行, 核对真实的 query
- 调 `.env` 里 `IKUAI_IP_KEYS` 和 `IKUAI_MAC_KEYS` 加上真实字段名

### Entra 登录一直转圈

- 手机连 WiFi 后能不能打开 `https://login.microsoftonline.com`
- 不能的话说明免认证白名单没加齐, 回 iKuai 加

---

## 安全清单

- [x] Client Secret 只在本地密码管理器 + VPS `.env`, 不进 git
- [x] `.env` 权限 600
- [x] Portal 只绑 `127.0.0.1:28080`, 不直接暴露公网
- [x] OIDC state + nonce 防 CSRF / 重放
- [x] `tid` claim 校验防跨租户
- [x] Guest (`#EXT#`) 拦截
- [x] 签名 cookie 15 分钟过期
- [x] 安全响应头 (CSP / X-Frame-Options / etc.)
- [ ] Client Secret 日历提醒 2028-04-08 前轮换
- [ ] (未来) Prometheus 监控 + 到期自动告警
