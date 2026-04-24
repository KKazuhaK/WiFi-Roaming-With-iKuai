# Mode C · 预构建镜像部署 (Synology Container Manager / iKuai UI)

这条路适合**目标机器上不方便跑 git / docker build**, 但能通过 Web UI 导入 Docker 镜像的场景:

- **Synology NAS** — DSM 7 的 Container Manager 套件
- **iKuai (x86_64)** — 高级应用 → 插件管理
- 任何别的只能通过 UI 管 Docker 的设备

流程:

1. 找一台能 `docker build` 的机器 (你的 VPS / 其它 LAN 盒子) 构建出两个镜像, 导出成 tarball
2. Tarball 上传到目标机器
3. 目标机器的 UI 里导入镜像 + 建容器

**前提**: 目标机器是 **linux/amd64** 或跟你构建机相同的架构。`docker build` 默认构出
构建机的 CPU 架构, 架构错了 tarball 载不进去或容器 "exec format error"。

32-bit iKuai (`x32` edition) 跑不了, 因为 Caddy 官方镜像不发 386 版。

---

## Step 1 · 在构建机上打 tarball

需要有本仓库源码 + Docker 能跑 build 的机器。VPS 上最合适 (有 Docker, 跟 Synology 通常都是 amd64)。

```bash
# 在仓库根目录
cd /opt/wifi-portal     # 你主部署的仓库就行, git pull 确保最新代码
git pull

# 构建
docker build -t kazuha/wifi-portal:latest ./portal
docker build -t kazuha/caddy-cloudflare:latest -f deploy/Dockerfile.caddy deploy/

# 导成一个 tarball (包含两个镜像, 一个文件传一次省事)
docker save -o /tmp/wifi-portal-stack.tar \
    kazuha/wifi-portal:latest \
    kazuha/caddy-cloudflare:latest

ls -lh /tmp/wifi-portal-stack.tar    # 大约 300-500 MB
```

---

## Step 2 · tarball 上传到目标机器

**到 Synology**:
- File Station 里建 `/volume1/docker/wifi-portal/` 目录
- 把 tarball 拖进去 (或者用 rsync / scp 到同一路径)

**到 iKuai (如果 64-bit)**:
- 开 iKuai 的 Samba / FTP 服务
- 上传到任意路径, 记下绝对路径 (比如 `/mnt/sda1/wifi-portal-stack.tar`)

---

## Step 3 · UI 里导入镜像

### Synology

1. **Container Manager** → 左边 **映像檔**
2. 顶部 **新增** → **從檔案新增**
3. 选上传的 tarball (`/volume1/docker/wifi-portal/wifi-portal-stack.tar`)
4. 导入完应该能在列表看到 `kazuha/wifi-portal:latest` 和 `kazuha/caddy-cloudflare:latest` 两条

### iKuai

1. **高级应用** → **插件管理** → **添加**
2. **上传方式**: 引用镜像
3. **镜像路径**: 填 tarball 绝对路径
4. 确认

---

## Step 4 · 准备 `.env` + 可选的 `data/` 目录

回到目标机器的项目目录 (Synology: `/volume1/docker/wifi-portal/`, iKuai: 自己定),
建两个东西:

### `.env` 文件

File Station 里在项目目录 **新增文字檔案** → 命名 `.env` → 右键开启 Text Editor
(装 "Synology Text Editor" 套件), 贴内容:

```bash
# === Caddy ===
CLOUDFLARE_API_TOKEN=<你创建的 CF token>
ACME_EMAIL=me@kazuha.org
PORTAL_HOSTNAME=wifi.login.kazuhahub.com
PORTAL_HTTPS_PORT=28081

# === Portal — Entra ===
TENANT_ID=e72914d3-3d19-486e-be11-15c69540e02a
CLIENT_ID=199d45bd-7c7b-4eed-983e-758c8aa12d18
CLIENT_SECRET=<密码管理器里那个>

# === Portal — iKuai ===
IKUAI_APPKEY=<这个站点 iKuai 的 appkey>
IKUAI_IP_KEYS=user_ip,ip,ipaddr
IKUAI_MAC_KEYS=user_mac,mac,usrmac,devmac

# === Portal — 自身 ===
PUBLIC_URL=https://wifi.login.kazuhahub.com:28081
LISTEN_ADDR=0.0.0.0:28080
SESSION_SECRET=<跟其他部署共用的同一个 hex 字符串>

# === Brand ===
BRAND_NAME=Kazuha Hub
BRAND_COLOR=#2563eb

# === Admin ===
ADMIN_EMAILS=me@kazuha.org
#ADMIN_GROUP_IDS=<如果你配了 Entra 组, 填 GUID>

# 持久化数据 (访客码 / MAC 封禁 / iKuai 放行策略 / 事件日志) 默认全部写到容器内 /data/,
# docker-compose.yml 里已经把 /data bind-mount 到 ./data/, 不需要在这里配置任何 *_PATH.

# === Duo (可选) ===
#DUO_IKEY=
#DUO_SKEY=
#DUO_CLIENT_ID=
#DUO_CLIENT_SECRET=
#DUO_API_HOST=api-XXXXXXXX.duosecurity.com
#ALLOWED_EMAIL_DOMAINS=kazuha.org,kazuhahub.com,kazuhahub.cn
```

**注意**: `SESSION_SECRET` 要跟你 VPS 和 LAN 盒子上填的是**同一个值**, 否则 admin
cookie 跨部署不互通。如果 Windows 手头没 openssl, PowerShell 里:
```powershell
[Convert]::ToHexString((1..32 | ForEach-Object { [byte](Get-Random -Max 256) }))
```

### `data/` 目录

File Station 里在项目目录 **新增資料夾** → 命名 `data`。容器启动入口会先修正 `data`
目录所有权, 再降权给 `portal` 用户写
`guest-codes.json` / `denylist.json` / `ikuai-policy.json` / `events.jsonl`。
如果底层文件系统不允许改所有权或写入, Portal 会在启动时直接报 `/data` 不可写。

---

## Step 5 · UI 里新建专案

### Synology

1. Container Manager → 左边 **專案** → 顶部 **新增**
2. 弹窗:
   - **專案名稱**: `wifi-portal`
   - **路徑**: 点 **瀏覽** → 选 `/docker/wifi-portal/` → 确定
   - **來源**: 选 **"上傳 docker-compose.yml"**
   - **檔案**: 点 **瀏覽**, 选本仓库的 [`deploy/prebuilt-image/docker-compose.yml`](./docker-compose.yml)
     (先从 Windows 保存一份, 或者直接右键 GitHub raw 链接保存)
3. 下一步 → 会解析出 `portal` 和 `caddy` 两个服务, 镜像都用 `kazuha/...` (UI 确认能匹配到 Step 3 导入的那两个)
4. 下一步 → Web Portal 那步**跳过**
5. 勾 **建立專案後啟動** → **完成**

几秒内 Caddy 会自动申请证书 (日志里看 `certificate obtained successfully`), Portal 起 healthy.

### iKuai

iKuai UI 不支持 compose, 只能一个容器一个容器手配:

**Portal 容器**:
- 镜像: `kazuha/wifi-portal:latest`
- 名称: `wifi-portal`
- 重启策略: `unless-stopped`
- 端口: 不发布 (Caddy 内网访问)
- 挂载: `/mnt/.../wifi-portal/data → /data`
- 环境变量: 按 `.env` 里的内容一条条填

**Caddy 容器**:
- 镜像: `kazuha/caddy-cloudflare:latest`
- 名称: `wifi-portal-caddy`
- 重启策略: `unless-stopped`
- 端口: `28081 → 28081`
- 挂载: **只要两条 volume 给证书持久化** (`caddy-data:/data` 和 `caddy-config:/config`,
  Caddyfile 已经烤进镜像不用挂). 如果 iKuai UI 不支持 named volume, 就用 bind
  mount 挂到 `/mnt/.../wifi-portal-caddy/data/` 和 `.../config/`
- 环境变量: `CLOUDFLARE_API_TOKEN` / `PORTAL_HOSTNAME` / `PORTAL_HTTPS_PORT` / `ACME_EMAIL`
- **网络**: 得和 Portal 容器在同一个 docker 网络, Caddyfile 里写的是 `reverse_proxy portal:28080` 靠容器名解析

iKuai 的 Docker 是否支持容器名 DNS 未验证, 做不到的话走 `host.docker.internal:28080` 或直接 IP。

---

## Step 6 · iKuai 那边 DNS 劫持

不管 Portal 跑在 Synology 还是 iKuai 自己, 你每个站点的 iKuai 路由器都要配:

```
静态 DNS: wifi.login.kazuhahub.com → <Portal 宿主 LAN IP>
自定义认证 URL: https://wifi.login.kazuhahub.com:28081/portal
```

---

## Step 7 · Entra Redirect URI

Entra App Registration → Authentication → Redirect URIs, 确认有这条:
```
https://wifi.login.kazuhahub.com:28081/auth/callback
```

多个站点共用同一个 App Registration + 这条 Redirect URI, 不用重复加。

---

## 升级流程

Portal 代码改了 / Caddy 要升级时:

1. 构建机 `git pull` + `docker build` + `docker save` → 新 tarball
2. 上传覆盖旧 tarball
3. UI 里重新导入镜像 (Synology: **映像檔** → 选旧镜像 → 删除 → 重新 **從檔案新增**; 或者 tag 一致直接覆盖)
4. 重启专案 / 容器

比 `git pull && docker compose up -d --build` 步骤多, 但全程网页可点。

---

## 和其他模式的对比

| | A: VPS | B: LAN 盒子 | C: 预构建镜像 (本模式) |
|---|---|---|---|
| 目标设备 | VPS + aaPanel | Pi / x86 mini-PC / OpenWrt Docker | Synology NAS / iKuai UI |
| 源码 on 设备 | 要 | 要 | **不要** |
| Docker build on 设备 | 要 | 要 | **不要** |
| 主要 UI | CLI | CLI | 网页点点点 |
| 升级 | `git pull && up --build` | 同左 | 重新 build tarball + 上传 + 导入 |
| 适合 | 公网入口 | 多站点主力 | 家用 NAS / 运维偏网页派 |

所有模式 **共享同一份 `SESSION_SECRET`** → admin 一次登录所有 /admin 都认。
