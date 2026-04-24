# Kazuha Hub Roaming

统一的团队 WiFi 接入方案. 用户在 Captive Portal 输入**组织邮箱**:

- **Duo 用户** (已在 Duo 注册 Mobile) → 直接跳 Duo Universal Prompt 页, 选设备 / 批准推送 → 放行
- **非 Duo 用户** (纯 MSA / FIDO 等) → 自动 fallback 到 Entra SSO 流程 → 放行
- **外部 Guest 账号** (UPN 含 `#EXT#`) → 拒绝
- **访客** (没有组织账号) → 点"访客码登录", 输入管理员发的一次性码 → 放行

所有四类**共用同一个 SSID `Kazuha Hub Roaming`**. 每条流程最终都通过 iKuai 自定义认证
(`type=20`) 把设备 MAC / IP 放进路由器白名单.

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
│   ├── session.go             # HMAC 签名 cookie (wifi + admin)
│   ├── oidc.go                # Entra OIDC 流程
│   ├── duo.go                 # Duo Auth API 客户端 (preauth 探测)
│   ├── duo_universal.go       # Duo Universal Prompt (OIDC) 客户端
│   ├── admin.go               # 访客码内存存储 + 随机生成
│   ├── ikuai.go               # iKuai 放行 token 生成
│   ├── i18n.go                # 三语字符串 (zh-cn/zh-tw/en)
│   ├── templates/             # login.html / error.html / admin.html
│   ├── static/                # logo + 头像
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
| `IKUAI_APPKEY` | iKuai 云面板 "生成" 得到 (Phase 4) |
| `IKUAI_USER_ID_PREFIX` | 审计日志账号列前缀, 默认 `Kazuha_Hub` → `Kazuha_Hub-<upn>` |
| `PUBLIC_URL` | `https://wifi.login.example.com` |
| `SESSION_SECRET` | 运行 `openssl rand -hex 32` 生成一次, 贴进来 |
| `BRAND_NAME` | `Kazuha Hub` 或你喜欢的 |
| `BRAND_COLOR` | 默认 `#2563eb`, 可改 |
| `BRAND_LOGO_URL` | 留空用 `static/logo+title-circle{,-darkmode}.png` |
| `DUO_IKEY` / `DUO_SKEY` | **Duo Auth API** application (preauth 探测用) |
| `DUO_CLIENT_ID` / `DUO_CLIENT_SECRET` | **Duo Web SDK** application (Universal Prompt) |
| `DUO_API_HOST` | 两个 Duo application 共用, 形如 `api-XXXXXXXX.duosecurity.com` |
| `ALLOWED_EMAIL_DOMAINS` | 启用 Duo 时必填, 逗号分隔 (`example.org,example.com,example.net`) |
| `ADMIN_EMAILS` | 访客码管理后台 (`/admin`) 准入白名单, 逗号分隔 |

### Duo 两种 Application 怎么建

本项目分流流程需要 Duo Admin Panel 里**两个** Application:

1. **"Auth API"** — 仅用于 preauth (问 Duo "这用户在吗?"), 不发推送.
   - 取 `Integration key` / `Secret key` → `DUO_IKEY` / `DUO_SKEY`

2. **"Web SDK"** — Universal Prompt OIDC, 真正的 2FA 交互.
   - 配置时 Redirect URI 必须填 `https://wifi.login.example.com/auth/duo-callback`
   - 取 `Client ID` / `Client secret` → `DUO_CLIENT_ID` / `DUO_CLIENT_SECRET`

两个 Application 的 API hostname 相同 → `DUO_API_HOST`. 五个 Duo 字段要么全填要么全空.

### 访客码 Admin

`ADMIN_EMAILS` 列出的那些账号, 用 Entra SSO 登录 `/admin` 可以:
- 单条添加 (自动生成 10 位数字, 或自定义)
- 批量生成 (纯数字 / 纯字母 / 数字+字母, 任意长度)
- 设置过期时间 (绝对) 或限时 (相对)
- 筛选 (全部 / 已使用 / 未使用 / 已过期) + 搜索
- 单条删除 / 批量删除失效

访客码存在容器内存, 重启会丢, 重新生成即可.

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
