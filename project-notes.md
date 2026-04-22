# Kazuha Hub Roaming · 项目进度笔记

> 这份文件记录已确认的配置值和 Phase 进展，边做边补。
> **禁止把 Client Secret / iKuai appkey / SESSION_SECRET 写入本文件。** 这类值只在 VPS 本地 `.env` 里。

---

## 已确认的决策

| 项 | 值 |
|---|---|
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

### Phase 2 · VPS 基础环境（并行，你在做）
- [ ] 2A Cloudflare 加 A 记录 `wifi.login.example.com` → VPS IP（灰云）
- [ ] 2B aaPanel 添加站点
- [ ] 2C aaPanel 配反代到 `http://127.0.0.1:28080`
- [ ] 2D aaPanel 申请 Let's Encrypt + 启用强制 HTTPS
- [ ] 2E 验证 `curl -I https://wifi.login.example.com` 返回 502

### Phase 3 · Portal 代码（并行，已交付）
- [x] Go 源码：main / config / session / oidc / ikuai / i18n
- [x] 中英双语模板 login.html / error.html
- [x] Dockerfile（多阶段，Alpine 运行时）
- [x] docker-compose.yml（绑 127.0.0.1，日志限额，healthcheck）
- [x] .env.example（所有变量含说明）
- [x] README.md 部署指南
- [x] 静态代码审查通过（无编译错误，无关键安全/逻辑 bug）
- [ ] Phase 2 完工后：`docker compose up -d --build` 实际编译 + 起服务
- [ ] Entra OIDC 端到端自测（假 IKUAI_APPKEY 先跑通 Entra 这段）

---

## 下一步

Phase 2：VPS 基础环境
- DNS 解析 `wifi.login.example.com` → VPS 公网 IP
- aaPanel 加网站 + 申请 TLS 证书
- aaPanel 配反向代理到 `127.0.0.1:28080`
- 建项目目录 `/opt/wifi-portal`
