# Mode C · 部署到 iKuai 自带 Docker

这是除了**模式 A (VPS + aaPanel Nginx)** 和**模式 B (LAN 盒子 + Caddy)** 之外的**第三种**部署选项。
原理同 B (DNS 劫持 + 内置 Caddy), 只是宿主机换成 iKuai 路由器本身, 省一台独立 LAN 盒子。

选这种方式的前提:
- iKuai 是 Enterprise x86 版, "高级应用 → 插件管理" 里能看到 Docker 镜像管理
- 路由器有富余的 CPU / 内存 / 磁盘 (小型号不推荐)
- 能接受 **iKuai 固件升级后可能需要重新部署容器** 的运维成本 (历史上有坑)

生产建议仍然是 **模式 B (独立 LAN 盒子)** 最稳, 这个模式 C 适合想极简硬件的场景。

---

## 架构

```
设备 (连 Kazuha Hub WiFi)
    │
    │  1. 访问任何 HTTPS → iKuai 捕获 302 到 https://wifi.login.example.com:28081/portal
    │  2. iKuai DNS 劫持: wifi.login.example.com → iKuai 自己的 LAN IP (例如 192.168.1.1)
    │  3. HTTPS 到 192.168.1.1:28081
    │
    ▼
iKuai 路由器 (LAN IP 192.168.1.1)
    ├── 路由 / DHCP / captive portal (iKuai 本职)
    ├── [容器] wifi-portal-caddy  监听 28081, TLS 终止, DNS-01 证书
    │                ↓ compose 网络 / bridge
    └── [容器] wifi-portal        监听 28080, Portal 业务逻辑
```

证书申请走 Cloudflare DNS-01, 跟模式 B 一样。

---

## 步骤 1: 在开发机上打包 tarball

需要一台装了 Docker 能 build 镜像的机器 (Windows / macOS / Linux 都行), 有本仓库源码:

```bash
# 在仓库根目录
cd WiFi-Roaming-With-iKuai

# Build 两个镜像
docker build -t kazuha/wifi-portal:latest ./portal
docker build -t kazuha/caddy-cloudflare:latest -f deploy/Dockerfile.caddy deploy/

# 打成一个 tarball (包含两个镜像)
docker save -o wifi-portal-stack.tar \
    kazuha/wifi-portal:latest \
    kazuha/caddy-cloudflare:latest

# 确认一下
ls -lh wifi-portal-stack.tar    # 大约 300-500 MB
```

**架构提示**: 开发机 build 出来的镜像是你机器的 CPU 架构。iKuai x86 通常是 `amd64`,
如果你在 ARM Mac 上 build, 加 `--platform linux/amd64`:
```bash
docker build --platform linux/amd64 -t kazuha/wifi-portal:latest ./portal
docker build --platform linux/amd64 -t kazuha/caddy-cloudflare:latest -f deploy/Dockerfile.caddy deploy/
```

---

## 步骤 2: tarball 传到 iKuai

iKuai 有内置的 **FTP 服务** 或 **Samba 服务** (高级应用菜单里), 开一个就能从你机器推文件到 iKuai 的存储。
或者走 SCP (如果 iKuai 开了 SSH)。

假设传到 iKuai 的绝对路径是 `/mnt/sda1/wifi-portal-stack.tar` (实际路径看你 iKuai 挂载了什么磁盘)。

---

## 步骤 3: iKuai UI 导入镜像

1. iKuai 后台 → **高级应用** → **插件管理** → **添加**
2. **上传方式**: 选 **引用镜像**
3. **镜像路径**: 填 `/mnt/sda1/wifi-portal-stack.tar` (步骤 2 那个路径)
4. 点 **确认**

iKuai 会调用 `docker load`, 完成后两个镜像 (`kazuha/wifi-portal` 和 `kazuha/caddy-cloudflare`) 都进了它的 Docker 环境。

---

## 步骤 4: 创建 Portal 容器

iKuai UI 里添加容器实例 (具体入口可能在"插件管理"的镜像列表旁边 → "启动"或"创建实例"):

- **镜像**: `kazuha/wifi-portal:latest`
- **容器名**: `wifi-portal`
- **重启策略**: `unless-stopped` (或 "总是重启")
- **端口映射**: **不映射** (内部只让 Caddy 访问, 不要暴露到宿主或 LAN)
- **挂载**:
  | 宿主路径 | 容器路径 | 说明 |
  |---|---|---|
  | `/mnt/sda1/wifi-portal-data/` (自己建) | `/data` | 访客码持久化 |
- **环境变量** (iKuai UI 应该有 env 添加入口, 挨个填):

  | 变量 | 值 |
  |---|---|
  | `TENANT_ID` | `00000000-0000-0000-0000-000000000000` |
  | `CLIENT_ID` | `00000000-0000-0000-0000-000000000000` |
  | `CLIENT_SECRET` | 本地密码管理器里的 Value |
  | `IKUAI_APPKEY` | iKuai 云控制台给的 appkey (每站点独立) |
  | `IKUAI_USER_ID_PREFIX` | `Kazuha_Hub` |
  | `PUBLIC_URL` | `https://wifi.login.example.com:28081` |
  | `LISTEN_ADDR` | `0.0.0.0:28080` |
  | `SESSION_SECRET` | 同你 VPS / LAN 盒子的那一份 (SSO share-cookie) |
  | `ADMIN_EMAILS` | `you@example.org` |
  | `ADMIN_GROUP_IDS` | Entra Security Group GUID (如果你启用了组准入) |
  | `GUEST_CODES_PATH` | `/data/guest-codes.json` |
  | `BRAND_NAME` | `Kazuha Hub` |
  | `BRAND_COLOR` | `#2563eb` |
  | 若启用 Duo | `DUO_IKEY` / `DUO_SKEY` / `DUO_CLIENT_ID` / `DUO_CLIENT_SECRET` / `DUO_API_HOST` / `ALLOWED_EMAIL_DOMAINS` |

点 **启动**, 容器应该进 Running 状态。

---

## 步骤 5: 创建 Caddy 容器

- **镜像**: `kazuha/caddy-cloudflare:latest`
- **容器名**: `wifi-portal-caddy`
- **重启策略**: `unless-stopped`
- **端口映射**: `28081 → 28081` (iKuai 主机的 28081 接收外部 HTTPS)
- **挂载**:
  | 宿主路径 | 容器路径 | 说明 |
  |---|---|---|
  | `/mnt/sda1/wifi-portal-caddy/Caddyfile` | `/etc/caddy/Caddyfile` (只读) | Caddy 配置 |
  | `/mnt/sda1/wifi-portal-caddy/data/` | `/data` | 证书存放 |
  | `/mnt/sda1/wifi-portal-caddy/config/` | `/config` | Caddy 自身状态 |
- **环境变量**:
  | 变量 | 值 |
  |---|---|
  | `CLOUDFLARE_API_TOKEN` | CF API Token |
  | `PORTAL_HOSTNAME` | `wifi.login.example.com` |
  | `PORTAL_HTTPS_PORT` | `28081` |
  | `ACME_EMAIL` | 你的邮箱 |

Caddyfile 内容 (先在 iKuai 文件系统上准备好再挂载):
```
{
    email {$ACME_EMAIL}
}

{$PORTAL_HOSTNAME}:{$PORTAL_HTTPS_PORT} {
    tls {
        dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    }
    reverse_proxy wifi-portal:28080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
        header_up Host {host}
    }
}
```

注意里面 `reverse_proxy wifi-portal:28080` — 需要 iKuai 的 Docker 支持**容器名 DNS 解析**
(同一默认 bridge 网络里按容器名访问)。新版 Docker 默认支持, 老版本可能只能按 IP 访问。

### 如果 iKuai Docker 不支持容器名 DNS

退而求其次: 让 Portal 容器也发布端口到 iKuai 主机的 127.0.0.1, Caddy 通过 `host.docker.internal` 或 docker0 bridge IP 访问。

改法:
1. Portal 容器的端口映射: 加 `127.0.0.1:28080 → 28080`
2. Caddyfile 里把 `reverse_proxy wifi-portal:28080` 改成 `reverse_proxy host.docker.internal:28080` (若 iKuai Docker 支持) 或 `reverse_proxy 172.17.0.1:28080` (docker0 网关 IP, 最保险)

启动容器。

---

## 步骤 6: 验证 Caddy 拿到证书

iKuai UI 里看 Caddy 容器的日志 (应该有个"查看日志"按钮), 预期几秒内:
```
{"level":"info","msg":"trying to solve challenge","identifier":"wifi.login.example.com","challenge_type":"dns-01"}
{"level":"info","msg":"certificate obtained successfully"}
{"level":"info","msg":"serving initial configuration"}
```

卡住最常见原因:
- `CLOUDFLARE_API_TOKEN` 权限不对 — `curl -H "Authorization: Bearer $TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify` 在你 dev 机测一下
- env 里值前后有空格或引号
- iKuai 路由器自己出不了网 (检查 iKuai 上游 DNS / WAN)

---

## 步骤 7: iKuai DNS 劫持

iKuai 后台 → **网络设置** → **DNS 设置** (或域名过滤 / 静态 DNS, 不同固件版本名字不同) → 加一条:

```
域名: wifi.login.example.com
IP:   <iKuai 自己的 LAN IP, 例如 192.168.1.1>
```

这样连在 Kazuha Hub Roaming SSID 上的设备查询域名时, 返回的是 iKuai 自己的 LAN IP, 请求直接打到 iKuai 上的 28081 → Caddy → Portal。

---

## 步骤 8: iKuai 自定义认证 URL 加端口

iKuai 后台原来 Phase 4 配的 captive portal URL 改成**带 :28081 端口**:

```
https://wifi.login.example.com:28081/portal
```

---

## 步骤 9: Entra Redirect URI

如果你跟其他 LAN 盒子共用同一个 Entra App Registration (应该是), 那 Redirect URI 列表里
`https://wifi.login.example.com:28081/auth/callback` 应该已经在了。没在就加上。

---

## 步骤 10: 真机端到端测试

1. 手机连 Kazuha Hub Roaming SSID
2. 浏览器打开任何 http 网站 → 被 captive 302 到 portal 页
3. 走 Entra / Duo 登录 → 回跳 → 放行 → 正常上网

---

## 升级

改了 Portal 代码或 Caddy 配置要升级时:

1. 在开发机重新 `docker build` + `docker save`
2. 把新 tarball 推到 iKuai (覆盖原来那个或换新路径)
3. iKuai UI → 插件管理 → 选镜像 → **重新加载** (或删旧的 + 引用新的)
4. 重启容器 (Portal 和 / 或 Caddy)

运维步骤比 `git pull && docker compose up -d --build` 繁琐得多, 这是 iKuai UI-only 的代价。

---

## 和模式 A / B 的取舍

| | A: VPS | B: LAN 盒子 | C: iKuai Docker |
|---|---|---|---|
| 硬件 | 一台 VPS 服务所有站点 | 每站点一台小机器 | 每站点 iKuai 自己 |
| TLS | aaPanel Nginx ACME HTTP-01 | Caddy DNS-01 | Caddy DNS-01 |
| 部署方式 | `docker compose up` | `docker compose up` | iKuai UI 点点点 |
| 升级 | `git pull && up --build` | `git pull && up --build` | build + save + 上传 + UI 重新加载 |
| 日志 / 调试 | CLI 顺手 | CLI 顺手 | 只能 iKuai UI 翻 |
| 公网攻击面 | 有 | 无 | 无 |
| 硬件成本 | 低 | 中 | 最低 |
| 运维成本 | 低 | 低 | 中偏高 |
| 对路由器稳定性影响 | 无 | 无 | 有 (占 iKuai 资源) |

建议: **主要站点跑 B, 硬件受限或临时站点跑 C, 公网测试 / admin 入口跑 A**。三种可以混合, SESSION_SECRET 都共享 → admin 一次登录全都认。
