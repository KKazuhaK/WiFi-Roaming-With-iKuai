# Kazuha Hub Roaming

统一的 WiFi 接入方案. 用户在 Captive Portal 输入**账号**:

- **Duo 用户** (已在 Duo 注册 Mobile) → 直接跳 Duo Universal Prompt 页, 选设备 / 批准推送 → 放行
- **非 Duo 用户** (纯 MSA / FIDO 等) → 自动 fallback 到 Entra SSO 流程 → 放行
- **外部 Guest 账号** (UPN 含 `#EXT#`) → 拒绝
- **访客** (没有组织账号) → 点"访客码登录", 输入管理员发的一次性码 → 放行

所有四类**共用同一个 SSID `Kazuha Hub Roaming`**. 每条流程最终都通过 iKuai 自定义认证
(`type=20`) 把设备 MAC / IP 放进路由器白名单.

这份 README 覆盖架构、部署、安全模型和运维。

## 三种部署模式

| | **A — 外部反代** | **B — LAN 盒子** | **C — 预构建镜像 UI** |
|---|---|---|---|
| 适合场景 | 公网 VPS, aaPanel/Nginx 管 TLS | 站点内网 Pi / mini-PC | Synology NAS / iKuai UI (Docker 但没 CLI) |
| 源码 on 设备 | ✓ (git clone) | ✓ | **×** 只上传镜像 tarball |
| 主要 UI | CLI | CLI | 网页点击 |
| TLS | 外部反代 | Caddy DNS-01 | Caddy DNS-01 |
| 公网攻击面 | 有, 靠 App 层三道限流 | **无**, iKuai DNS 劫持 | **无** |
| admin 远程访问 | ✓ | ✗ (要在 WiFi 网里) | ✗ |

**A/B 共用同一份** [`deploy/docker-compose.yml`](./deploy/docker-compose.yml),
靠 `.env` 里的 `COMPOSE_PROFILES` 切换:
- 留空 → 模式 A, 只跑 Portal, 外部反代处理 TLS
- `COMPOSE_PROFILES=caddy` → 模式 B, 额外起 Caddy 做 DNS-01 TLS

**C 用 [`deploy/prebuilt-image/`](./deploy/prebuilt-image/) 下独立的 compose**,
跳过 build 直接拉已加载的镜像。步骤看 [`deploy/prebuilt-image/README.md`](./deploy/prebuilt-image/README.md)。

三种可以混合部署, `SESSION_SECRET` 共享 → admin 一次登录所有 /admin 都认。

---

## 目录

```
WiFi-Roaming-With-iKuai/
├── README.md                  # 本文
├── portal/                    # Go 源码 + Dockerfile + 前端模板
│   ├── main.go                # HTTP 路由
│   ├── config.go              # 环境变量读取
│   ├── session.go             # HMAC 签名 cookie (wifi + admin)
│   ├── oidc.go                # Entra OIDC 流程
│   ├── duo.go                 # Duo Auth API 客户端 (preauth 探测)
│   ├── duo_universal.go       # Duo Universal Prompt (OIDC) 客户端
│   ├── admin.go               # 访客码存储 (内存 + 可选 JSON 落盘) + 随机生成
│   ├── auth_proceed.go        # /auth/proceed 中转, 防账号枚举
│   ├── ratelimit.go           # 失败计数 + IP 短时冷却 + clientIP 解析
│   ├── ikuai.go               # iKuai 放行 token 生成
│   ├── eventlog.go            # 结构化事件日志 (登录 + admin 审计) + JSONL 持久化 + CSV 导出
│   ├── i18n.go                # 三语字符串 (zh-cn/zh-tw/en)
│   ├── templates/             # login.html / error.html / admin.html
│   ├── static/                # logo + 头像
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── .env.example           # 环境变量模板, 不含真值
│   └── go.mod
└── deploy/
    ├── docker-compose.yml           # 模式 A/B 共用
    ├── Caddyfile                    # 会烤进 Caddy 镜像, 源码部署也作 bind-mount
    ├── Dockerfile.caddy             # 模式 B / C 要 build
    ├── aapanel-nginx-snippet.conf   # 只有模式 A 要参考
    └── prebuilt-image/              # 模式 C: tarball 导入 + UI 部署
        ├── docker-compose.yml       # 只有 image:, 不 build
        └── README.md
```

---

## Phase 3 · 部署

前置: Phase 1 (Entra App Registration) + Phase 2 (DNS + 反代 / TLS 基础设施)
已全部完成。

### 步骤 1: 源码上机器

**模式 A (VPS)**:
```bash
sudo mkdir -p /opt/wifi-portal
sudo chown $USER:$USER /opt/wifi-portal
cd /opt/wifi-portal
```

**模式 B (LAN 盒子)**: 建议目录换成 `/opt/wifi-portal-intranet/` 防跟模式 A 同机冲突。

把本仓库里的这些传上去:
- `portal/` 整个目录
- `deploy/docker-compose.yml`
- **(仅模式 B)** `deploy/Caddyfile` 和 `deploy/Dockerfile.caddy`
- `portal/.env.example` → 拷成 `.env`

`git clone` 或 `scp -r` 都行, 最终目录:

```
/opt/wifi-portal/              # 模式 A
├── docker-compose.yml
├── .env                       <- 马上要填
└── portal/                    <- Go 源码

/opt/wifi-portal-intranet/     # 模式 B 追加
├── docker-compose.yml
├── Caddyfile
├── Dockerfile.caddy
├── .env
└── portal/
```

> **不要直接 `cd deploy/ && docker compose up`** — compose 里 `build.context: ./portal`
> 是相对 compose 文件的位置, 从仓库 `deploy/` 跑会找 `deploy/portal/` 不存在而失败。
> 正确做法就是上面那样, 把 compose + Caddyfile + Dockerfile.caddy 跟 `portal/` 放同一级目录。

### 步骤 2: 填 .env

```bash
cd /opt/wifi-portal        # 或 wifi-portal-intranet
cp portal/.env.example .env
chmod 600 .env             # 只允许你自己读
vim .env                   # 或 nano
```

`.env.example` 里的字段按需填。**关键的模式切换**:

```bash
# 模式 A: 留空 (或不要这一行). 只起 portal 容器, 外部反代处理 TLS.
COMPOSE_PROFILES=

# 模式 B: 设成 caddy. 同时多起 caddy 容器, 自动申请证书.
COMPOSE_PROFILES=caddy
```

### 两种模式共通的变量

| 变量 | 来源 |
|---|---|
| `TENANT_ID` | `e72914d3-3d19-486e-be11-15c69540e02a` |
| `CLIENT_ID` | `199d45bd-7c7b-4eed-983e-758c8aa12d18` |
| `CLIENT_SECRET` | 你本地密码管理器里 `portal-prod-2026-v2` 的 Value |
| `IKUAI_APPKEY` | iKuai 云面板 "生成" 得到 (Phase 4) |
| `PUBLIC_URL` | 模式 A: `https://wifi.login.kazuhahub.com` &nbsp;/&nbsp; 模式 B: `https://wifi.login.kazuhahub.com:28081` (端口要对上) |
| `SESSION_SECRET` | 运行 `openssl rand -hex 32` 生成一次, 贴进来. 多站点想共享 admin cookie 填同一个 |
| `BRAND_NAME` | `Kazuha Hub` 或你喜欢的 |
| `BRAND_COLOR` | 默认 `#2563eb`, 可改 |
| `BRAND_LOGO_URL` | 留空用 `static/logo+title-circle{,-darkmode}.png` |
| `DUO_IKEY` / `DUO_SKEY` | **Duo Auth API** application (preauth 探测用) |
| `DUO_CLIENT_ID` / `DUO_CLIENT_SECRET` | **Duo Web SDK** application (Universal Prompt) |
| `DUO_API_HOST` | 两个 Duo application 共用, 形如 `api-XXXXXXXX.duosecurity.com` |
| `ALLOWED_EMAIL_DOMAINS` | 启用 Duo 时必填, 逗号分隔 (`kazuha.org,kazuhahub.com,kazuhahub.cn`) |
| `ADMIN_EMAILS` | 访客码管理后台 (`/admin`) 准入白名单, 逗号分隔, 可留空走组模式 |
| `ADMIN_GROUP_IDS` | Entra Security Group Object ID 列表 (可选), 组成员自动 admin |

iKuai 账号显示不需要额外 env 配置, 会自动按认证方式生成: `SSO-<upn>`, `Duo-<upn>`, `Guest-<id>`.

### 仅模式 B 才要填的变量

| 变量 | 来源 |
|---|---|
| `CLOUDFLARE_API_TOKEN` | CF Dashboard → API Tokens → Create, `Zone:DNS:Edit` 权限, 限定 `kazuhahub.com` zone. 多站点复用同一个 |
| `ACME_EMAIL` | 你的邮箱, LE/ZeroSSL 到期提醒用 |
| `PORTAL_HOSTNAME` | 默认 `wifi.login.kazuhahub.com`, 多站点都填同一个 (靠 iKuai DNS 劫持分流) |
| `PORTAL_HTTPS_PORT` | 默认 `28081`, 想占 443 改这里 |

**模式 B 额外步骤**:
- Entra App Registration 加 Redirect URI: `https://wifi.login.kazuhahub.com:28081/auth/callback`
- 每个站点 iKuai 后台加静态 DNS: `wifi.login.kazuhahub.com` → 本地 LAN 盒子 IP
- 每个站点 iKuai 自定义认证 URL 改成: `https://wifi.login.kazuhahub.com:28081/portal`

更详细的 模式 B 故障排查 (CF API token 权限 / 证书申请卡住 / iKuai DNS 不生效) 见本 README 末尾 "故障排查".

### Duo 两种 Application 怎么建

本项目分流流程需要 Duo Admin Panel 里**两个** Application:

1. **"Auth API"** — 仅用于 preauth (问 Duo "这用户在吗?"), 不发推送.
   - 取 `Integration key` / `Secret key` → `DUO_IKEY` / `DUO_SKEY`

2. **"Web SDK"** — Universal Prompt OIDC, 真正的 2FA 交互.
   - 配置时 Redirect URI 必须填 `https://wifi.login.kazuhahub.com/auth/duo-callback`
   - 取 `Client ID` / `Client secret` → `DUO_CLIENT_ID` / `DUO_CLIENT_SECRET`

两个 Application 的 API hostname 相同 → `DUO_API_HOST`. 五个 Duo 字段要么全填要么全空.

### 访客码 Admin

Admin 准入有两种方式, 任一成立即通过, 可共存:

1. **`ADMIN_EMAILS`** — UPN 白名单, CSV 格式直接列人, 改动要重启容器
2. **`ADMIN_GROUP_IDS`** — Entra Security Group 的 Object ID (GUID), 组成员
   自动有 admin 权限。**推荐**: 人员变动只改 AAD, 不用改 env 不用重启

#### 启用 Group 方式 (一次性配置)

**A. App Registration 加 `groups` claim**

Entra Admin Center → App registrations → `Kazuha Hub WiFi Portal` →
**Token configuration** → **Add groups claim** (**不是** `Add optional claim` —
`groups` 不在 optional claims 列表里, 有独立的按钮)。弹出对话框里:

- **Select group types**: 勾 `Security groups` (匹配下面 B 步要建的组类型)
- **Customize token properties by type**: 保持默认 (Group ID 格式)
- **Save**

保存完列表里会出现一条 `groups` claim, 下次 id_token 就会带 `"groups": [...]` 数组.

**B. 创建 / 选一个 Security Group**

Groups → New group → Type = Security, 加成员 = 几位 admin → 创建好后去
Overview 复制 **Object ID** (GUID 格式).

**C. 填进 `.env`**

```
ADMIN_GROUP_IDS=<刚才复制的 Object ID>
```

可以多个逗号分隔。`ADMIN_EMAILS` 也可以保留 (两种方式并行), 或改成空走纯 group
模式。重启容器生效。

#### Admin 能做什么

`/admin` 页面顶部是**概览看板** (7 张卡片): 24h 登录数、7d 登录数、7d 失败占比、有效访客码、封禁 IP / MAC、全部访客码总数。下面是五个 tab:

> 当前在线设备数 / 在线时长直接到 iKuai 后台查, Portal 不重复造轮子。

**访客码**
- 单条添加 (自动生成 10 位数字, 或自定义)
- 批量生成 (纯数字 / 纯字母 / 数字+字母, 任意长度)
- 设置单次限时 (激活后这次 iKuai 放行多久) 和过期时间 (多久后不能再激活; 留空表示永不过期)
- 设置每个码的**最大使用次数** (0 = 不限)
- 筛选 (全部 / 已使用 / 未使用 / 已过期) + 搜索
- 单条删除 / 批量删除失效

**放行策略**
- 按认证方式设置 iKuai 放行策略 (上传 / 下载 / 超时 / comment)

**MAC 封禁**
- 手动封禁 / 解除封禁
- **导出 / 导入 CSV** (列: `mac, reason, banned_by, banned_at`, UTF-8 BOM 防 Excel 乱码, 导入幂等且跳过非法 MAC)

**限流状态**
- 看 IP 冷却 / 邮箱失败 / MAC 失败计数, 一键解除或封禁
- 从访客码 MAC 失败记录一键封禁设备

**事件日志**
- 时间倒序展示登录事件 (SSO / Duo / 访客码) 和 admin 审计 (添加 / 删除码 / 限流操作 / 策略变更等)
- 按类型 / 方式 / 结果 / 时间范围 / 对象关键字过滤, 默认看 7 天
- 导出 CSV (UTF-8 BOM, 中文列头, Excel 直开)
- 默认每 30 秒自动刷新 (仅当此 tab 活动时)
- **敏感数据处理**: 不记录密码 / token; 访客登录事件只记码尾 4 位; admin 访客码管理审计记录完整码, 便于追溯操作

**iKuai 放行策略**: `/admin` 的"放行策略"页可分别设置 SSO 成员、
Duo 成员、访客码的 `upload` / `download` / `comment`; SSO / Duo 还可设置 `timeout`。
启动默认值走 env:

```
IKUAI_SSO_UPLOAD=0       IKUAI_SSO_DOWNLOAD=0       IKUAI_SSO_TIMEOUT=0       IKUAI_SSO_COMMENT=
IKUAI_DUO_UPLOAD=0       IKUAI_DUO_DOWNLOAD=0       IKUAI_DUO_TIMEOUT=0       IKUAI_DUO_COMMENT=
IKUAI_GUEST_UPLOAD=0     IKUAI_GUEST_DOWNLOAD=0     IKUAI_GUEST_COMMENT=
```

`upload` / `download` 单位是 KB/s, `0` = 不限速; `timeout` 单位是分钟, `0` = 不过期。
`comment` 会写进 iKuai 侧记录, 不要放敏感信息或完整访客码。访客码不走全局 `timeout`;
放行时会使用该访客码自己的"单次限时"作为 iKuai `timeout`, 与码本身的过期时间分开。

#### 持久化

所有持久化文件**统一写到容器内 `/data/`**, `docker-compose.yml`
里已经把 `/data` bind-mount 到宿主机 `./data/`,跨 `docker compose up --build / down / rm`
不丢数据。路径在代码里固定 (没有任何 `*_PATH` env, 用户也不需要配):

| 文件 | 内容 |
|---|---|
| `/data/guest-codes.json` | 访客码 |
| `/data/denylist.json` | MAC 永久封禁列表 |
| `/data/ikuai-policy.json` | iKuai 放行策略 (admin 改的会写进来) |
| `/data/ratelimit-state.json` | IP 冷却历史次数 (配合 `IP_BAN_ESCALATE_AT` 用) |
| `/data/events.jsonl` | 事件日志 (登录 + admin 审计, JSONL, 默认保留 7 天) |

要换位置改 `docker-compose.yml` 的 `volumes: - ./data:/data` 一行即可。
容器启动入口会先把 bind-mounted `./data` 修成 `portal` 用户可写, 再降权运行 Portal。
Portal 启动时还会做一次 `/data` 写入探测; 如果宿主目录权限不对, 会直接 fatal, 避免误以为持久化生效。
落盘采用原子写 (tmp + rename), 启动加载失败会 fatal 避免覆盖损坏文件。
事件日志写盘失败只 log 不阻塞业务路径 — 不是关键路径, 丢一条也不影响放行。

事件日志 schema (JSONL 每行一条):
```json
{"time":"2026-04-24T14:32:18Z","kind":"login","subject":"me@kazuha.org",
 "result":"success","method":"duo","mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.1.50"}
{"time":"2026-04-24T14:31:04Z","kind":"admin_action","subject":"me@kazuha.org",
 "result":"success","method":"admin","detail":"add code=1234567890"}
```

`tail -f data/events.jsonl` 可在宿主机实时看流。保留期想改: `EVENT_LOG_RETENTION_DAYS=7`。

### 步骤 3: 起服务

```bash
cd /opt/wifi-portal              # 或 wifi-portal-intranet
docker compose up -d --build     # 模式由 .env 里 COMPOSE_PROFILES 决定
docker compose ps                # 确认容器都 Up
docker compose logs -f portal
```

**模式 A** 预期日志:
```
Portal 启动, 监听 0.0.0.0:28080, public URL: https://wifi.login.kazuhahub.com
```
且只有 `wifi-portal` 一个容器。外部 Nginx / aaPanel 反代到 `127.0.0.1:28080`。

**模式 B** 预期日志里多一段 Caddy 的, 稍等十几秒会看到:
```
wifi-portal-caddy  | {"level":"info","msg":"certificate obtained successfully"}
wifi-portal-caddy  | {"level":"info","msg":"serving initial configuration"}
wifi-portal        | Portal 启动, ..., public URL: https://wifi.login.kazuhahub.com:28081
```
`docker compose ps` 能看到 `wifi-portal` + `wifi-portal-caddy` 两个容器都 Up。

如果 Caddy 一直卡在 "obtaining certificate" + CF API 错误, 99% 是 `CLOUDFLARE_API_TOKEN`
权限不对 / 值多了空白。本地验证 token 好使:

```bash
curl -H "Authorization: Bearer <你的 token>" \
  https://api.cloudflare.com/client/v4/user/tokens/verify
# 返回 "status": "active" 即可
```

### 步骤 4: 端到端自测 (Phase 4 之前)

```bash
# 1. 健康检查
curl https://wifi.login.kazuhahub.com/healthz
# 预期: ok

# 2. /portal 不带参数直接访问 (模拟有人直接敲域名, 不是从 iKuai 跳过来)
curl -I https://wifi.login.kazuhahub.com/portal
# 预期: HTTP/2 400 (返回 "session lost" 页)
# 这是正常的. 说明 Portal 认得路由, 但拒绝了非 iKuai 来源的访问.

# 3. /portal 带伪造的 user_ip + mac 参数
curl -I "https://wifi.login.kazuhahub.com/portal?user_ip=192.168.1.100&mac=aa:bb:cc:dd:ee:ff"
# 预期: HTTP/2 200, Set-Cookie: kz_wifi_sess=...

# 4. 浏览器打开上面第 3 条的 URL, 应该看到登录页.
#    点 "Sign in with Microsoft", 走完 Entra 登录.
#    Entra 回跳后会报错 (iKuai 放行失败因为 appkey 是假的), 但这一步能到
#    说明 Entra OIDC 端到端都通了.
```

---

## Phase 4 · iKuai 接入

- [ ] 4.1 iKuai 云控制台 → 自定义认证 → 生成 appkey
- [ ] 4.2 VPS `/opt/wifi-portal/.env` 填 `IKUAI_APPKEY`, 再 `docker compose restart portal`
- [ ] 4.3 iKuai 路由器配 Web 认证 → 自定义认证, Portal URL 填 `https://wifi.login.kazuhahub.com/portal` (模式 B 带 `:28081`)
- [ ] 4.4 iKuai 绑 SSID `Kazuha Hub Roaming` 到此认证
- [ ] 4.5 iKuai 免认证白名单加上 Entra / Duo / Portal 域名 (见下)
- [ ] 4.6 真机连 WiFi 端到端: Entra 登录 → 放行 → 上网
- [ ] 4.7 拒绝 Guest 真实测试 (拿一个 UPN 含 `#EXT#` 的外部账号, 验证拒绝页)

### iKuai 免认证白名单 (必须)

Captive Portal 启动后, 浏览器必须能**先**访问这些域名才能走完登录流程。
把它们全部加到 iKuai 的 "免认证 IP / 免认证域名" (iKuai 支持通配,
`*.example.com` 这种写法可以用):

```
# Microsoft Entra (必需)
login.microsoftonline.com
login.microsoft.com
login.windows.net
login.live.com
aadcdn.msftauth.net
aadcdn.msauth.net
logincdn.msauth.net
device.login.microsoftonline.com

# Duo (启用 Duo 才需要; 你的 DUO_API_HOST 也包含在通配里)
*.duosecurity.com

# 自家域名
wifi.login.kazuhahub.com
portal.ikuai8-wifi.com
```

**故意不加白名单** (这些必须被 iKuai 劫持才会弹 captive portal):
- `connectivitycheck.gstatic.com` (Android 探测)
- `captive.apple.com` (iOS 探测)
- `www.msftconnecttest.com` (Windows 探测)

加白这些会让 OS 误以为已联网, 不弹登录页, 用户连了 WiFi 没浏览器自动跳就以为坏了。

**Graph API**: 当前 admin 组成员从 id_token 的 `groups` claim 直接读,
**不调 graph.microsoft.com** — 没必要白名单这一条 (留着也无害)。

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

### `502 Bad Gateway` (模式 A · 外部反代报 502)

- 容器是不是起来了: `docker compose ps`
- 端口绑对了没: `ss -tlnp | grep 28080` 应该看到 docker-proxy 在听
- 容器内部能通吗: `docker compose exec portal wget -O- http://127.0.0.1:28080/healthz`

### `502` 来自 Caddy + 日志写 `connect: connection refused` (模式 B/C)

Caddy 日志 (`docker compose logs caddy` 或容器详情页日誌) 里看到:
```
{"level":"error","msg":"dial tcp 172.X.X.X:28080: connect: connection refused", ...}
```
curl 得到 `HTTP/2 502`, 但 Portal 容器却显示 healthy — 这是**同一个坑**的两面:

- **Portal 的 `LISTEN_ADDR` 默认是 `127.0.0.1:28080`**, 只让容器内自己 loopback 访问
- healthcheck 跑的是 `wget 127.0.0.1/healthz`, 自己打自己能通 → Synology / Docker 把容器标成 healthy
- 但 Caddy 从隔壁容器走 compose 网络过来打 `172.X.X.X:28080`, 被 TCP RST 掉 → 502

**修法**: 确保 `LISTEN_ADDR=0.0.0.0:28080`。两种方式:

1. 写进 compose 的 `environment:` 段 (最保险, 不看 .env 也生效):
   ```yaml
   portal:
     env_file:
       - .env
     environment:
       - LISTEN_ADDR=0.0.0.0:28080
   ```
   这也是 `deploy/docker-compose.yml` 和 `deploy/prebuilt-image/docker-compose.yml` 的默认写法。

2. 写进 `.env`:
   ```
   LISTEN_ADDR=0.0.0.0:28080
   ```
   不能被注释掉, 不能漏。

改完 **必须 recreate 容器** (不能只 restart — restart 不重读 compose):
- CLI: `docker compose up -d --force-recreate portal`
- Synology Container Manager: 專案 → 停止 → 删除容器 → 啟動 (或"重新部署"按钮)

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

### 日志里看到 `限流` 或 `IP 失败超限`

不是 bug, 是规则生效了。细节见下面"安全 / 防滥用"章节, 对应调阈值 env 即可。

---

## 安全 / 防滥用

Portal 面向公网, 默认就带以下应用层防御, **不需要额外配置** 就能跑起来。
阈值全部走 env, 想调的话见 `.env.example` 里 "限流 / 防滥用" 段, 留空走默认。

### 设备封禁与三层失败计数

| 规则 | 键 | 默认阈值 | 成功清零条件 | 命中动作 |
|---|---|---|---|---|
| **1** · `/auth/start` | email | 3 分钟 5 次 **或** 1 小时 20 次 | `/auth/callback` 或 `/auth/duo-callback` 成功 | 429 `rate_limited` |
| **5** · `/auth/guest-code` | session cookie 里签名的 MAC | 30 分钟 6 次 | 访客码正确 | 429 `rate_limited` |
| **6** · 全端点兜底 | IP (X-Real-IP) | 5 分钟累计 20 次任意失败 | 不自动, 冷却到期 | 冷却 2 分钟, 不升级永久 |

三层并行独立, 任一命中都返 429。**规则 6** 也会累加 "触发规则 1/5 本身" — 所以
同一个攻击者哪怕换邮箱也会在同 IP 上累加。邮箱计数是**单邮箱独立累计**,
不同邮箱不会互相叠加。

永久封禁只针对 **MAC denylist**:
- `/portal` 拿到 iKuai 传来的 MAC 后先查封禁列表, 命中则拒绝进入登录页
- `/auth/start` / `/auth/proceed` / SSO 回调 / Duo 回调 / 访客码验证都会复查 MAC
- MAC 可变 / 可伪造, 所以它是设备级运营封禁, 不是强身份边界
- 不封禁 UPN; 用户身份安全交给 SSO
- 不永久封禁 IP; DHCP IP 只做短时冷却

### 账号枚举防护

`/auth/start` 不再返回真实的 Duo / Entra URL — 而是返回随机 opaque token,
浏览器访问 `/auth/proceed?token=X` 才 302 到真正目的。响应对所有邮箱一致,
被 Duo `deny` 的账号也被路由到 Entra (让 Entra 自己拒), 不暴露 "deny" 信号。
攻击者想枚举谁在 Duo 得为每个邮箱跟一次 302, 成本翻倍且立刻触发规则 1/6。

### 阈值 env (全部可选, 默认已列在表里)

```
AUTH_EMAIL_FAILS_SHORT=5         AUTH_EMAIL_WINDOW_SHORT=3m
AUTH_EMAIL_FAILS_LONG=20         AUTH_EMAIL_WINDOW_LONG=1h
GUEST_CODE_MAC_FAILS=6           GUEST_CODE_MAC_WINDOW=30m
IP_FAILS_LIMIT=20                IP_FAILS_WINDOW=5m
IP_BAN_DURATION=2m               # IP 短时冷却时长
IP_BAN_ESCALATE_AT=999999        # 基本等于不升级永久 (≤0 显式禁用 + 跳过 banHistory 写盘)
AUTH_PROCEED_TTL=5m              # opaque token 存活时间
EVENT_LOG_RETENTION_DAYS=7       # 事件日志保留期
```

(所有持久化文件路径都固定在 `/data/`, 见上面"持久化"段, 没有 `*_PATH` env 可配。)

### 反代信任边界 (TRUST_PROXY)

Portal 的 IP 限流靠 `X-Real-IP` / `X-Forwarded-For` 拿真实客户端 IP。**默认信任** —
适合反代终结 TLS 的部署 (模式 A/B 都是)。

```
TRUST_PROXY=true     # 默认, 反代场景
TRUST_PROXY=false    # 直暴公网必须设, 否则攻击者伪造 X-Real-IP 绕过所有限流
```

> ⚠️ 安全要点: 直接把 Portal 端口暴露到公网时 *必须* `TRUST_PROXY=false`,
> 否则攻击者每个请求带 `X-Real-IP: <随机>` 让 IP 限流永远不累计。
> 启动时 Portal 检测 `LISTEN_ADDR` 不是 loopback 会打 warning。

`X-Forwarded-For` 解析时取 **最右** 那一段 (反代 append 的真客户端 IP),
攻击者伪造的部分被推到左侧自然失效。推荐反代显式设 `X-Real-IP $remote_addr`,
比 XFF 更稳。

### 时区 (TZ)

Portal 的 datetime-local 输入 (admin 设访客码过期时间) 按容器时区解析。
**默认 `TZ=UTC`** (docker-entrypoint.sh 内设)。

```
TZ=UTC                # 默认, admin 输入 "18:00" 当 18:00 UTC
TZ=Asia/Shanghai      # admin 输入 "18:00" 当 18:00 北京时间
```

CSV 导出 / admin 列表显示 / 日志时间戳全跟这个 env 走。

### 优雅退出 (SIGTERM)

`docker compose down` / `docker stop` 会发 SIGTERM, Portal 接到后:
1. `srv.Shutdown` (停接新连接, 在飞中请求 10s grace)
2. flush `banHistory` 的 dirty 状态到 `/data/ratelimit-state.json` (异步 flusher 平时 30s 一次,
   退出时强制同步一次, 防丢失 IP 冷却升级历史)
3. close EventLog file handle
4. 日志打 `clean exit`

kill -9 / OOM 会跳过这步, 最多丢 30s 内的 banHistory 增量。

### IP 短时冷却模型

为了避免 DHCP 误伤, IP 只做临时降速:

- 单 IP 5 分钟内累计 20 次失败 → 冷却 2 分钟
- 对已建立 Portal session 的请求, IP 判定同时使用 HTTP client IP 和签名 cookie 里的 iKuai `user_ip`
- SSO / Duo / 访客码成功后, 会清理该邮箱、该 MAC、HTTP client IP、cookie `user_ip` 的临时失败状态
- 失败次数按对应窗口自动过期: 邮箱 3 分钟 / 1 小时, 访客码 MAC 30 分钟, IP 5 分钟
- 前端只显示"操作过于频繁, 请在 X 分钟后再试"
- 不向用户暴露命中的是邮箱 / MAC / IP 哪条规则
- IP 冷却历史 (`/data/ratelimit-state.json`) 跨重启保留 — 仅当 `IP_BAN_ESCALATE_AT < 999999` 时生效, 默认基本等于不用
- 只有 MAC 永久封禁会提示联系管理员

### Admin 限流 / 封禁面板

`/admin` 页面有以下与安全相关的 tab:

**MAC 封禁**:
- 手动添加 MAC + 原因
- 解除 MAC 封禁
- 从"访客码 MAC 失败"行一键封禁该 MAC
- 导出 / 导入 CSV (跨环境批量同步, 导入幂等且跳过非法 MAC)

**限流状态**:
- 当前处于 IP 冷却期的 IP (规则 6)
- 有失败计数的邮箱 (规则 1)
- 有失败计数的 MAC (规则 5)
- 有失败计数但还没触发冷却的 IP

限流表每行有**解除**按钮, 点一下立即清该 key 的相应计数 / 解封。每 15 秒自动刷新,
也能手动刷新。管理员操作会打日志, 同时进事件日志 (`admin_action` 类型) 留审计痕迹。

**事件日志 / Dashboard** 的运营用法见上面"Admin 能做什么"段。
事件日志覆盖所有登录事件 (含限流命中) 和 admin 审计 — 出问题时这是排查的首要入口。

### 关键日志片段

```
限流: email 5/3m0s + 20/1h0m0s, MAC 6/30m0s, IP 20/5m0s → 冷却 2m0s, 不升级永久
MAC 封禁列表持久化: 已启用, path=/data/denylist.json
# ↑ 启动时打印, 确认阈值加载成功

auth/start 邮箱限流: me@kazuha.org short=3 long=3 ip=1.2.3.4
# ↑ 规则 1 命中

guest-code 按 MAC 限流: mac=aa:bb:cc:dd:ee:ff ip=1.2.3.4
# ↑ 规则 5 命中

IP 失败超限, 冷却 2m0s (第 1 次): 192.168.1.23 (累计=20 窗口=5m0s 原因=...)
# ↑ 规则 6 命中, 这里只是短时冷却

POST /auth/start -> 200 (32.1ms) client_ip=192.168.1.23 user_ip=192.168.1.23 mac=aa:bb:cc:dd:ee:ff ua="..."
# ↑ 每条请求日志都会带 HTTP client IP; 有签名 cookie 时也会带 iKuai user_ip / MAC

拒绝已封禁 MAC 访问 portal: mac=aa:bb:cc:dd:ee:ff ip=192.168.1.23
# ↑ MAC denylist 命中
```

### 爬虫

`/robots.txt` 返 `Disallow: /`, 模板里也打了 `<meta name="robots" content="noindex, nofollow">`。
正经爬虫 (Google / Bing 之类) 会跳过。恶意爬虫不理这个, 交给上面三条限流。

### 强烈建议: 按路由器 WAN IP 白名单 (Nginx 层)

Captive portal 只服务 "已连上 Kazuha Hub Roaming SSID 的设备"。那些设备的 HTTPS
请求从 iKuai 路由器 WAN 口出来, 目标 `wifi.login.kazuhahub.com`。所以**所有合法
流量都来自已知的少量路由器 WAN IP**, 别的 IP 碰到 `/portal` / `/auth/*` 只能是扫
描器或攻击者。

在 Nginx 层按路由器 WAN IP 白名单:
- 攻击者从任意公网 IP 根本连不到 `/auth/start`, 三层限流直接变成第二道保险
- MFA 轰炸通道从"需要三层代理穿透限流" → "根本没有入口"
- 扫描器 / 爬虫在 TCP 握手后第一时间 403

`deploy/aapanel-nginx-snippet.conf` 里有一段**默认注释掉**的配置块示例, 取消注释
并填上每个站点的路由器 WAN IP 就能用。IP 动态的话配合 ddclient / 定时刷新脚本。

> ⚠️ **前提**: 你的路由器 WAN 有相对固定的公网 IP (静态 IP / 家用宽带的半静态 PPPoE
> 都行)。纯动态 IP + 无 DDNS 的情况用这一层会经常自己误伤。

### 可选: `/admin` IP 白名单 (Nginx 层)

`/admin*` 已经被 Entra SSO 保护 — 不加白名单也安全。加了能把扫描器的探测在 Entra
之前就拦掉, 但基本属于锦上添花。

`deploy/aapanel-nginx-snippet.conf` 里有对应的注释示例。

### 不在 Portal 层解决的

以下攻击类型需要靠基础设施, Portal 代码层面不保护:

- **DDoS 打爆 Nginx / VPS 带宽** → 靠 CF / Nginx `limit_conn` / 运营商 DDoS 保护
- **发现源 IP 绕过反代直打 VPS** → 靠 iptables 只允许反代来源 IP
- **Duo API 配额被大量 preauth 耗尽** → 被规则 6 间接缓解; 真心担心可以在 Duo Admin Panel 给 Auth API 应用加阈值告警

---

## 安全清单

- [x] Client Secret 只在本地密码管理器 + VPS `.env`, 不进 git
- [x] `.env` 权限 600
- [x] Portal 不直接暴露公网 — 宿主端口只映射到 `127.0.0.1:28080` (模式 A 的外部反代可达) 或根本不发布 (模式 B/C 的 Caddy 经 compose 网络访问). 容器内部 `LISTEN_ADDR=0.0.0.0` 以便反代可达
- [x] OIDC state + nonce 防 CSRF / 重放
- [x] `tid` claim 校验防跨租户
- [x] Guest (`#EXT#`) 拦截
- [x] 签名 cookie 短期过期 (wifi 登录 15 分钟, admin 后台 1 小时)
- [x] 安全响应头 (CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy)
- [x] 三层失败计数 + IP 短时冷却 (规则 1 邮箱 / 规则 5 MAC / 规则 6 IP, 详见"安全 / 防滥用")
- [x] MAC 永久封禁列表 (持久化到 `/data/denylist.json`, 管理员在 `/admin` 维护, 支持 CSV 导入导出)
- [x] 账号枚举防护 (`/auth/start` → opaque token → `/auth/proceed` 中转)
- [x] `robots.txt` 拒爬 + 模板 `<meta robots noindex nofollow>`
- [x] 结构化事件日志 + admin 审计 (`/data/events.jsonl`, JSONL, 默认保留 7 天)
- [ ] Client Secret 日历提醒 2028-04-08 前轮换
- [ ] (未来) Prometheus 监控 + 到期自动告警
