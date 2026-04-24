# Kazuha Hub Roaming · 项目进度笔记

> 这份文件记录已确认的配置值和 Phase 进展，边做边补。
> **禁止把 Client Secret / iKuai appkey / SESSION_SECRET 写入本文件。** 这类值只在 VPS 本地 `.env` 里。

---

## 已确认的决策

| 项 | 值 |
|---|---|
| 代码仓库 | https://github.com/KKazuhaK/WiFi-Roaming-With-iKuai (Private) |
| CI | GitHub Actions (`.github/workflows/build.yml`: go vet + build + Docker 镜像构建) |
| 基础域名 | `example.com` |
| Portal 域名 | `wifi.login.example.com` |
| Portal 语言 | Go |
| Portal 运行方式 | Docker Compose |
| 反向代理 | aaPanel 自带 Nginx (OpenResty)，反代到 `127.0.0.1:28080` |
| Portal 监听端口 | `127.0.0.1:28080`（只绑 localhost，不公网暴露） |
| TLS | aaPanel 自动 (acme.sh) |
| 准入策略 | Entra 租户内 `userType == "Member"` 全员，Guest 被拒 |
| 准入判断方式 | 检查 id_token 的 `upn` claim 不含 `#EXT#` |
| 成员 UPN 格式 | `user@example.org` (Primary domain) |
| 租户内其他 custom domain | `example.com` (非 Primary，用于 Portal) |
| SSID · 人 | `Kazuha Hub Roaming` (Captive Portal) |
| SSID · IoT | `Kazuha Hub IoT` (WPA2-PSK) |
| UI 语言 | 中文 + 英文双语 (`Accept-Language` 自动 + `?lang=` 手动) |
| 品牌化 | 环境变量注入 logo URL + 主色 |

---

## Entra ID 配置（非 Secret）

| 字段 | 值 |
|---|---|
| Tenant ID | `00000000-0000-0000-0000-000000000000` |
| Client ID | `00000000-0000-0000-0000-000000000000` |
| App Registration 名称 | `Kazuha Hub WiFi Portal` |
| Redirect URI | `https://wifi.login.example.com/auth/callback` |
| Supported accounts | Single tenant |
| Client Secret 原版 (portal-prod-2026) | 已删除 ✓ |
| Client Secret 使用中 (portal-prod-2026-v2) | Value 存本地密码管理器 + 待写入 VPS `.env` |
| Client Secret 到期日历提醒 | TODO 填（新版创建日期 + 24 months - 14 天） |

### 日历提醒
- [ ] 2028-04-08：续 Entra Client Secret

---

## Phase 进度

- [x] Phase 1.1 Custom domain 加到 Entra 租户
- [x] Phase 1.2 团队成员账号（已有）
- [~] Phase 1.3 ~~创建 Security Group~~ — **已取消**（改为全租户 Member 准入）
- [~] Phase 1.4 ~~加自己进组~~ — **已取消**
- [x] Phase 1.5 App Registration
- [x] Phase 1.6 Client Secret 创建并轮换（v2 使用中）
- [~] Phase 1.7 ~~Groups claim 配置~~ — **已取消**（不再用 groups）
- [ ] Phase 1.8 Entra 侧端到端测试（等 Portal 部署后做）

**Phase 1 完成 ✓**

### Phase 2 · VPS 基础环境
- [x] 2A Cloudflare 加 A 记录 `wifi.login.example.com` → VPS IP（灰云）
- [x] 2B aaPanel 添加站点
- [x] 2C aaPanel 配反代到 `http://127.0.0.1:28080`（Sent Domain=`$host`, Cache=off）
- [x] 2D aaPanel 申请 Let's Encrypt 通配符证书 `*.login.example.com`（R12）+ HSTS
- [x] 2E 验证 `curl -I https://wifi.login.example.com` 返回 `HTTP/2 502` ✓

**Phase 2 完成 ✓**

### Phase 3 · Portal 代码 + 部署
- [x] Go 源码：main / config / session / oidc / ikuai / i18n
- [x] 中英双语模板 login.html / error.html
- [x] Dockerfile（多阶段，Alpine 运行时）
- [x] docker-compose.yml（绑 127.0.0.1，日志限额，healthcheck）
- [x] .env.example（所有变量含说明）
- [x] README.md 部署指南
- [x] 静态代码审查通过（无编译错误，无关键安全/逻辑 bug）
- [x] VPS 部署：`/opt/wifi-portal`, `docker compose up -d --build` 成功
- [x] 容器 healthy, 绑 127.0.0.1:28080
- [x] curl /healthz → 200 ok
- [x] curl /portal 无参数 → 400 session lost
- [x] curl /portal?user_ip=&mac= → 200 + Set-Cookie (HttpOnly/Secure/SameSite=Lax/Max-Age=900)
- [x] Entra OIDC 浏览器端到端 ✓
      - 登录页正常渲染（中英双语切换、K 头像、设备 IP/MAC 显示）
      - Entra 登录 → 回调 → `放行成员: upn=you@example.org` → 302 到 iKuai 云 portal
      - 浏览器在 iKuai 云 portal 那侧报 `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`（iKuai 的老 TLS），
        不是我们的 bug；真实场景 iKuai 路由器会在 LAN 内拦截不落到公网

**Phase 3 完成 ✓**

### Phase 3 后小改动
- 把 iKuai 放行接口 URL 从硬编码常量挪到 `IKUAI_WEBAUTH_URL` 环境变量，
  默认按官方文档 `https://portal.ikuai8-wifi.com/Action/webauth-up`。
  Phase 4 真实部署时如果固件要 http 或路由器 LAN IP，改 .env 即可不用重 build。
- 官方文档里示例还有 `user_id` / `custom_name` / `release_type=1` 这几个可选参数，
  目前不发，等 Phase 4 真实场景验证需要再加。

### Phase 3 已知小坑（供备案）
- 首次 build 失败: Dockerfile `COPY go.mod ./ + go mod download` 在无 go.sum 时不够，
  在 VPS 一次性 `docker run --rm -v ...:/src -w /src golang:1.22-alpine go mod tidy`
  生成 portal/go.sum 之后 build 成功。
- **待办**: 把 VPS 上生成的 `portal/go.sum` 拉回来 commit 进仓库，保证 CI / 后续机器 build 可复现。

---

## 下一步

Phase 2：VPS 基础环境
- DNS 解析 `wifi.login.example.com` → VPS 公网 IP
- aaPanel 加网站 + 申请 TLS 证书
- aaPanel 配反向代理到 `127.0.0.1:28080`
- 建项目目录 `/opt/wifi-portal`
