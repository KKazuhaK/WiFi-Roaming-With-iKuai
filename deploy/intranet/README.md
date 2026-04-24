# Kazuha Hub Roaming · 内网部署 (每站点一台 LAN 盒子)

这是可选的另一种部署方式, 跟仓库根的公网 VPS 方案**互斥但不冲突** —
你可以 4 个站点跑内网方案, 同时仓库根的 VPS 部署还在跑 (比如备用 / 远程 admin)。

## 它解决什么问题

公网 VPS 方案下 `wifi.login.example.com` 必须公网可达, 所以攻击面包括:

- 任何人都能打 `/auth/start` 触发 Duo preauth → 可能的 MFA 轰炸
- 账号枚举 (我们有 /auth/proceed 中转, 但仍有 timing 等边信道)
- 爬虫 / 扫描器 7×24 探测

内网方案下:

- Portal 只有 LAN IP, **公网上这个域名根本没东西可连**
- 设备必须先连上 Kazuha Hub Roaming SSID 才能解析到 portal
- TLS 证书依然真实可用 (通过 Cloudflare DNS-01 challenge 签发)

代价: `/admin` 也只能在 WiFi 网内访问 (或走 VPN / 内网穿透)。

---

## 前置条件

- 每个站点一台能跑 Docker 的机器. 最低配置: Raspberry Pi 4 / 旧笔记本 / 任何 x86 小主机 / 支持 Docker 的 NAS / OpenWrt 里的 dockerd
- Cloudflare 账号 (只用它的 API 做 DNS-01, 不代理流量 — 灰云就行)
- iKuai 路由器后台能改静态 DNS 条目

---

## 部署步骤 (每个站点都走一遍)

### 1. 在 LAN 盒子上准备目录

```bash
sudo mkdir -p /opt/wifi-portal-intranet
sudo chown $USER:$USER /opt/wifi-portal-intranet
cd /opt/wifi-portal-intranet

# 克隆仓库, 把 deploy/intranet/* 和 portal/ 拷过来
git clone https://github.com/KKazuhaK/WiFi-Roaming-With-iKuai.git /tmp/wifi-src
cp -r /tmp/wifi-src/deploy/intranet/. .
cp -r /tmp/wifi-src/portal .
rm -rf /tmp/wifi-src

# 最终结构应该是:
# /opt/wifi-portal-intranet/
# ├── docker-compose.yml
# ├── Dockerfile.caddy
# ├── Caddyfile
# ├── .env.example
# ├── README.md
# └── portal/
#     ├── Dockerfile
#     ├── main.go
#     └── ...
```

> 或者直接 `git clone` 整个仓库到别处, 在 `deploy/intranet/` 下跑 compose,
> 但要在 compose 里改 `build.context: ../../portal`. 独立目录更干净.

### 2. 申请 Cloudflare API Token (**只需一次, 4 站点复用**)

CF Dashboard → 右上头像 → **My Profile** → **API Tokens** → **Create Token**
→ 选 **Edit zone DNS** 模板 → 在 "Zone Resources" 里选 `Include` / `Specific zone`
/ `example.com` (只给这一个 zone 权限) → Continue → Create Token → 复制 token 字符串

同一个 token 在 4 个 LAN 盒子的 `.env` 里填相同值就行 — DNS-01 challenge 是按
域名验证, 跟源 IP 无关。一次申请, 所有站点共用。

### 3. 填 .env

```bash
cd /opt/wifi-portal-intranet
cp .env.example .env
chmod 600 .env
vim .env
```

需要填的:

| 变量 | 值 | 跨站点 |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | 第 2 步拿到的 | 4 站点**同一个** |
| `ACME_EMAIL` | 你的邮箱, 收到期提醒 | 同一个 |
| `PORTAL_HOSTNAME` | `wifi.login.example.com` (一般不变) | 同一个 |
| `PORTAL_HTTPS_PORT` | 默认 `28081` | 同一个 |
| `PUBLIC_URL` | `https://wifi.login.example.com:28081` (端口对上) | 同一个 |
| `SESSION_SECRET` | `openssl rand -hex 32` 生成一次 | **4 站点同值** (SSO share-cookie) |
| `TENANT_ID` / `CLIENT_ID` / `CLIENT_SECRET` | Entra App Registration | 同一个 |
| `IKUAI_APPKEY` | iKuai 云控制台生成 | **每站点独立** |
| Duo 相关 (可选) | 同 VPS 方案 | 同一份 |
| `ADMIN_EMAILS` / `ADMIN_GROUP_IDS` | 同 VPS 方案 | 同一份 |

> **大多数字段 4 站点都填一样的值**. 实际上你可以先在一个站点配好 `.env`, 改完之后
> `scp` 到其他 3 个站点, 只改 `IKUAI_APPKEY` 一个字段就行 (如果每个站点 iKuai
> appkey 不同的话; 同一个 iKuai 账号下的不同路由器可能共享 appkey).

### 3.5 Entra App Registration 加 Redirect URI

由于 HTTPS 跑在 **28081** 端口, Entra 那边的 Redirect URIs 列表要加上带端口的那个:

```
https://wifi.login.example.com:28081/auth/callback
```

Entra Admin Center → App registrations → `Kazuha Hub WiFi Portal` → Authentication
→ Redirect URIs → 加这一条 (原来 VPS 方案用的那条不带端口的保留, 两种部署可以并存)。

Duo Web SDK 不需要额外配 (redirect_uri 通过 JWT 签名验证, 不需要预注册)。

### 4. 启动

```bash
docker compose up -d --build

# 看 Caddy 申请证书进度, 预期几秒内看到 "certificate obtained"
docker compose logs -f caddy

# 看 Portal 启动
docker compose logs -f portal
```

预期 Caddy 日志里有:
```
{"level":"info","msg":"obtaining certificate","identifiers":["wifi.login.example.com"]}
{"level":"info","msg":"certificate obtained successfully"}
```

如果卡在 "obtaining certificate" 且有 cloudflare API 相关错误, 检查 API token 权限。

### 5. 测试从 LAN 访问

在 LAN 里另一台机器上 (或者 iKuai 路由器 shell 里):

```bash
# 绕过 DNS, 直接用 Host header + SNI + 端口测试 Caddy
curl -v --resolve wifi.login.example.com:28081:<LAN_IP_OF_BOX> \
  https://wifi.login.example.com:28081/healthz
# 预期: 证书有效 + 响应 "ok"
```

### 6. iKuai 配 DNS 劫持

iKuai 后台 → **网络设置** → **DNS 设置** / **域名过滤** / **静态 DNS**
(不同固件版本名字不同) → 添加一条:

```
wifi.login.example.com  →  <LAN 盒子 IP, 如 192.168.1.50>
```

保存生效后, 连在 Kazuha Hub Roaming SSID 上的任何设备访问该域名都会解析到 LAN 盒子。

### 7. iKuai 自定义认证 URL 带端口

Phase 4 配的 iKuai 自定义认证 URL 改成 **带 :28081 端口**:

```
https://wifi.login.example.com:28081/portal
```

(如果你把 PORTAL_HTTPS_PORT 改回 443 就不带端口, 用原来的 URL 就行)

设备 captive 时 302 到这个 URL — 通过上一步的 DNS 劫持, 实际打的是 LAN 盒子
28081 端口。

### 8. 免认证白名单可以收窄

原来 VPS 方案需要的 `wifi.login.example.com` 这一条白名单**可以去掉** (设备根本不走公网)。
但 Microsoft / Duo 那些还是要保留, 设备还是要从公网访问它们。

---

## 多站点

4 个站点各自跑一套, **大部分配置直接复用**:

| 配置 | 跨站点策略 |
|---|---|
| `CLOUDFLARE_API_TOKEN` | 同一个 token, 一次创建 4 处用 |
| `PORTAL_HOSTNAME` / `PUBLIC_URL` | 同一个域名 (配合 iKuai DNS 劫持, 各自解析到本地) |
| `PORTAL_HTTPS_PORT` | 同一个端口 (28081) |
| `TENANT_ID` / `CLIENT_ID` / `CLIENT_SECRET` | 同一个 Entra App Registration |
| `SESSION_SECRET` | **同一个值** — Entra SSO, admin 登一次 4 站点都认 |
| `ADMIN_EMAILS` / `ADMIN_GROUP_IDS` | 同一份 |
| Duo 相关 | 同一份 |
| `IKUAI_APPKEY` | 每站点独立 (看 iKuai 配置, 有可能多路由器共享一个 appkey) |
| 访客码存储 (`./data/`) | 每站点独立, 在 site A 加的码在 site B 不认 |

**操作流程**: 先在 site 1 配好 `.env` 并跑通, 然后 `scp .env site-N:/opt/wifi-portal-intranet/.env`,
每个站点只改 `IKUAI_APPKEY` 一个字段, 剩下 `docker compose up -d --build` 就行。

> **SESSION_SECRET 跨站共享的安全影响**: 任一 LAN 盒子的 secret 泄露 = 所有站点的
> admin cookie 可被伪造。盒子放可信内网, `.env chmod 600`, Docker socket 不乱授权
> 即可。用户确定这是可接受的 trade-off, 换来 admin 一次登录走遍所有站点的便利。
>
> 如果某天想轮换 secret, 4 个站点 `.env` 同步改 + 全部 `docker compose restart portal`,
> 所有 admin cookie 一起失效, 重新登录即可。

---

## 运维命令

```bash
docker compose logs -f caddy        # 证书续签时会看到日志
docker compose logs -f portal       # Portal 业务日志 (包括限流命中)
docker compose restart portal       # 改了 Portal 的 .env
docker compose restart caddy        # 改了 Caddyfile
docker compose pull && docker compose up -d --build   # 拉新代码 + 重建
docker compose down                 # 停掉 (caddy 的 caddy-data volume 保留)
```

### 备份证书

```bash
docker run --rm -v wifi-portal-intranet_caddy-data:/src -v $(pwd):/dst alpine \
  tar czf /dst/caddy-data-backup.tgz -C /src .
```

(卷名前缀 = 这个部署目录的名字, 具体名称用 `docker volume ls` 查.)

### 备份访客码

直接 `cp ./data/guest-codes.json /backup/` 就行, bind-mount 可见。

---

## 故障排查

### Caddy 一直申请不到证书

- CF API token 权限够吗? 必须至少 `Zone:DNS:Edit`。用 `curl -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify` 验证。
- zone 是不是在这个 token 的 scope 里? token 只给了某个 zone, 但 `PORTAL_HOSTNAME` 是别的域 → 失败。
- 盒子网络通不通? `docker compose exec caddy ping api.cloudflare.com`

### 设备打开 `wifi.login.example.com` 证书报错

- iKuai DNS 劫持生效了吗? `nslookup wifi.login.example.com` 在设备上应该返 LAN IP
- 如果返公网 IP → DNS 劫持规则没生效, 检查 iKuai 配置 + 设备 DNS 缓存 (重连 WiFi)

### 能解析但浏览器报 `ERR_CONNECTION_REFUSED`

- Caddy 容器挂了? `docker compose ps`
- 防火墙? `sudo ufw status` / `sudo iptables -L`, 确认 80/443 对 LAN 开放
