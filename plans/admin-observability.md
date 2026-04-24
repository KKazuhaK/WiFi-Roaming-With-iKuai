# Admin Observability · Implementation Plan

> Status: Planning — written by a prior session, to be executed in a fresh session.
> Scope locked by user. Deliver in phases, each phase merges cleanly.

## Goal

Give admins visibility into what the Portal is doing. Currently every event
(user login, admin action, rate-limit hit) only exists in `docker logs`. This
plan adds a structured, queryable event log + a few dashboards on top of it.

## In scope

1. **登录历史** (auth event stream)
2. **Admin 操作审计** (admin action log)
3. **活跃设备看板** (who's connected right now)
5. **Dashboard** (summary counters at top of /admin)
6. **Denylist CSV import/export** (bulk ops on existing MAC denylist)

## Out of scope (user excluded these)

- #4 MAC 备注 / 标签
- Webhook / Slack 通知
- 管理面板里直接改 .env 配置
- 额外 MFA 层

---

## What's already there (do NOT duplicate)

Before writing anything, read these to understand current state:

- `portal/admin.go` — guest code store with JSON persistence (tmp+rename atomic write pattern)
- `portal/denylist.go` — MAC denylist, already has `IsMACDenied`, add/remove (verify exact API)
- `portal/ratelimit.go` — failCounter / ipBanList / banHistory, all with `snapshot()` methods
- `portal/main.go` — `/admin/*` handlers + `requireAdmin` helper
- `portal/templates/admin.html` — has tab navigation (`.admin-tab` / `.admin-section`),
  existing panels for guest codes + ratelimit
- `portal/config.go` — env parsing with `envOr`, `envOrInt`, `envOrDuration` helpers

The JSON-file persistence pattern is settled — follow it (see `GuestCodeStore`):
- Load on startup (fail fatal if malformed)
- Write on every mutation with `os.WriteFile(tmp) + os.Rename(tmp, real)`
- Don't hold lock during disk I/O... actually existing code holds lock during
  save, keep that pattern for consistency

---

## Phase 1 · Event log foundation

**File**: new `portal/eventlog.go`

**Struct**:

```go
type Event struct {
    Time    time.Time `json:"time"`
    Kind    string    `json:"kind"`    // see Kind constants below
    Subject string    `json:"subject"` // user UPN / guest-xxxxx / admin UPN
    Result  string    `json:"result"`  // "success" / "denied" / "rate_limited" / "error"
    Method  string    `json:"method"`  // "sso" / "duo" / "guest_code" / "admin"
    MAC     string    `json:"mac,omitempty"`
    IP      string    `json:"ip,omitempty"`
    Detail  string    `json:"detail,omitempty"`
}

const (
    KindLogin       = "login"        // WiFi 登录事件
    KindAdminAction = "admin_action" // 后台管理操作
)
```

**Store** `EventLog`:
- `Append(Event)` — 加锁, in-memory slice append, 同步 JSONL 追加到文件 (一次 `os.OpenFile(..., O_APPEND)` + `json.Encode`), 失败只 log 不阻塞业务
- `Query(filter) []Event` — 返回匹配的事件, 最新在前, 加 limit
- `Prune()` — 根据保留期删除老 entries (见下面存储策略)
- `gcLoop()` — 周期性调 Prune, 默认每小时一次
- 如果 `persistPath == ""` → 纯内存, 没有文件 I/O

**Storage**: JSON Lines 格式 (每行一个 `Event`). 理由:
- 追加 O(1), 不用 read-whole-file-rewrite
- 轻量可 `tail -f` 看
- Prune 时重写全文件即可 (cold path, 频率低)

**Retention**:
- env `EVENT_LOG_RETENTION_DAYS` 默认 `7`
- env `EVENT_LOG_PATH` 默认 `/data/events.jsonl`
- 留空 path = 纯内存, 容器重启丢

**API internal**: 在 `App` struct 加 `eventLog *EventLog`, main.go 初始化。

**Acceptance**:
- 单元级: 手动调 Append 几条, Query 返回对, Prune 按时间截断对
- 重启后能从文件恢复 (启动时读 JSONL 入内存)

---

## Phase 2 · Wire login events (feature #1)

`main.go` 在以下成功 / 失败点加 `a.eventLog.Append(Event{...})`:

| Trigger | Kind | Subject | Result | Method | Detail |
|---|---|---|---|---|---|
| `handleCallback` 放行成员 (SSO) | login | user.UPN | success | sso | — |
| `handleCallback` 拒绝 Guest (#EXT#) | login | user.UPN | denied | sso | "guest blocked" |
| `handleDuoCallback` 放行成员 | login | username | success | duo | — |
| `handleGuestCode` 放行访客 | login | upn (guest-xxx) | success | guest_code | `"code=..."` (最后 4 位足够) |
| `handleGuestCode` 码错 | login | "(guest)" | denied | guest_code | "invalid_code" |
| 任何 429 rate_limited | login | email 或 MAC | rate_limited | 对应 method | rule name |
| `/auth/proceed` 被 denylist 拒 | login | "(unknown)" | denied | - | "mac_denylist" |

admin 登录成功走 `finishAdminLogin` → 用 Kind=admin_action 记一条 "admin 登录"。

**Acceptance**:
- 手机连 WiFi 走完 Duo, /admin 的事件表里能看到一条 login/success/duo
- 输错访客码 2 次, 看到 2 条 login/denied/guest_code
- 被限流时也能看到

---

## Phase 3 · Wire admin audit events (feature #2)

所有 `requireAdmin` 能过的 POST handler 都要 emit 一条:

| Handler | Detail 内容 |
|---|---|
| `handleCodeCreate` | `"add code=<code>"` 或 `"add auto-gen"` |
| `handleCodeBatch` | `"batch count=<n> type=<num/alpha/...>"` |
| `handleCodeDelete` | `"delete code=<code>"` |
| `handleCodeDeleteExpired` | `"delete-expired deleted=<n>"` |
| `handleRateLimitReset` | `"reset type=<t> key=<k>"` |
| `handleRateLimitResetAll` | `"reset-all"` + 计数 |
| denylist add/remove | `"mac=<m> ban"` / `"mac=<m> unban"` |
| iKuai policy 编辑 | `"policy <profile>: <field> <old>→<new>"` |

所有 Kind=admin_action, Subject=admin.UPN。

**Acceptance**:
- /admin 页里对访客码做 5 次不同操作, 事件表里 5 条对应的 admin_action
- Result 一律填 "success", 失败路径不 emit (避免噪音)

---

## Phase 4 · Event viewer UI in admin.html

新 tab "事件日志" 在现有的 admin-nav 里挂一个。页面:

```
[筛选] Kind: [全部/登录/Admin操作]  Method: [全部/SSO/Duo/访客码]
       Result: [全部/成功/拒绝/限流]  [时间范围: 24h/7d 选择]
       [导出 CSV]

时间       | 类型 | 对象            | 方法      | 结果    | MAC | IP | 详情
14:32:18   | 登录 | you@example.org  | Duo       | 成功    | aa:bb... | 192.168.1.50 |
14:31:04   | 管理 | you@example.org  | 后台      | 成功    |          |              | add code=12345
...
```

- `GET /admin/events/query?kind=&method=&result=&since=&until=&limit=500` → JSON
- `GET /admin/events/export.csv?<same filters>` → CSV 下载
- 默认按时间倒序, 每页 500 条 + "加载更多" 按钮 (或直接无分页, 500 条上限够用)
- 自动刷新 30 秒一次 (polling, 跟限流面板一样风格)

**Acceptance**:
- /admin 点进"事件日志"能看到 Phase 2/3 的事件
- 筛选各维度都能用
- CSV 下载文件能用 Excel 打开, 列头中文

---

## Phase 5 · Active device view (feature #3)

**简化路径 (选这个)**: Portal 里自己维护一个内存映射, 不调 iKuai API。精度差一点 (看不到主动断开), 但实现简单, 信息对 admin 还是有用的。

数据结构: `map[string]ActiveDevice` (key = MAC)

```go
type ActiveDevice struct {
    MAC       string
    UserID    string    // upn 或 guest-xxx
    IP        string
    Method    string    // sso / duo / guest_code
    FirstSeen time.Time // 第一次放行时间
    LastSeen  time.Time // 最近一次同 MAC 放行时间
}
```

更新点: 每次成功放行时 `activeDevices.track(mac, user, ip, method)`:
- 有同 MAC → 更新 LastSeen + UserID/IP/Method (用户切了)
- 无 → 新建 + FirstSeen = LastSeen = now

Prune: `gcLoop` 每 15 分钟跑一次, 删掉 `LastSeen` 超过 `ACTIVE_DEVICE_WINDOW` 的条目。默认 `ACTIVE_DEVICE_WINDOW=24h` (env 可调)。

UI: admin-nav 加一个"活跃设备" tab, 列 MAC / UserID / IP / Method / FirstSeen / LastSeen / "最近活跃 XX 分钟前"。

这不是持久化的 — 重启清零。可接受 (数据随手重建)。

**Acceptance**:
- 3 个设备先后连上并登录, /admin 活跃设备面板看到 3 条
- 其中一个再次登录 (同 MAC, 重连 WiFi), LastSeen 更新
- 24h 没活动后自动消失

---

## Phase 6 · Dashboard (feature #5)

在现有的 /admin 首页顶部加一条 summary bar (在 admin-nav 下面, 访客码表格上面)。不用新 tab, 永远可见。

**要显示的数字**:
- 今日登录 (24h, from eventLog query result=success kind=login)
- 本周登录 (7d)
- 失败登录占比 (7d)
- 当前活跃设备数 (from activeDevices)
- 当前有效访客码数 (from guestCodes, 未过期 + 未用完)
- 当前封禁 IP 数 (from ipBans.snapshot())
- 当前封禁 MAC 数 (from denylist)

**实现**: 服务端渲染一次, 放到 adminPageData 里传进 admin.html 模板。不需要单独端点。

```go
type DashboardStats struct {
    LoginsToday      int
    LoginsWeek       int
    FailedRate7d     float64 // 0..1
    ActiveDevices    int
    ActiveGuestCodes int
    BannedIPs        int
    BannedMACs       int
}
```

UI: 一行 4 × 2 grid of cards, 每个显示数字 + label。简单, 10 行 HTML。

**Acceptance**:
- 数据正确 (跟事件日志里数一遍对得上)
- 不拖累页面加载 (都在内存, <50ms)

---

## Phase 7 · Denylist CSV import/export (feature #6)

看 `portal/denylist.go` 里 Store 的现有 API。需要确认有:
- `List() []DenyEntry`
- `Add(mac, reason, by string)`
- `Remove(mac string)`

(不是的话要加)

**Export**: `GET /admin/denylist/export.csv` → 表头 `mac,reason,banned_by,banned_at`, UTF-8 BOM 防 Excel 乱码。

**Import**: `POST /admin/denylist/import` 接受 multipart `file`, 解析 CSV:
- 每行必须有 mac (必填)
- reason / banned_by / banned_at 可选
- 非法 MAC 格式跳过, 返回 `{imported: N, skipped: M, errors: [...]}`

UI: 现有 denylist 面板加两个按钮 "导出 CSV" / "导入 CSV" (file picker)。

**Acceptance**:
- Export → Import 回来 (同 CSV), denylist 状态不变 (幂等)
- 手造一个带 3 行的 CSV (2 正常 1 非法 MAC) → imported=2 skipped=1
- Excel 打开 export 显示中文不乱码

---

## 文件 / 代码分布预估

新增:
- `portal/eventlog.go` — ~180 行

改动:
- `portal/main.go` — 新 handlers + emit 调用, 约 +120 行
- `portal/config.go` — 3 个新 env, +10 行
- `portal/templates/admin.html` — 事件日志 tab + 活跃设备 tab + dashboard cards + denylist CSV 按钮, +250 行
- `.env.example` — 3 个新 env 文档, +15 行
- `README.md` — 事件日志章节 + 保留期说明, +30 行

总预估: 约 600 行, 纯新增为主, 对现有代码干扰小。

---

## 新增 env 全表

```env
# 事件日志 (Phase 1)
EVENT_LOG_PATH=/data/events.jsonl   # 空 = 纯内存
EVENT_LOG_RETENTION_DAYS=7          # 保留期

# 活跃设备 (Phase 5)
ACTIVE_DEVICE_WINDOW=24h            # 多久不活动后从列表中剔除
```

所有都是可选, 留空走默认。

---

## 推荐分 commit 顺序

1. `eventlog: foundation (struct + store + JSONL persistence)` — 只加 `eventlog.go`, 不接入业务
2. `eventlog: wire login events into /auth/* handlers`
3. `eventlog: wire admin audit into /admin/* handlers`
4. `admin UI: event log viewer tab (query + csv export)`
5. `admin: active device tracking + view tab`
6. `admin: dashboard summary cards`
7. `admin: denylist csv import/export`

每个 commit 独立可 build 可回滚。

---

## 测试计划 (手动, 因为没单元测)

跑完所有 phases 之后, 走一遍冒烟测试:

1. 真机连 WiFi 走 Duo → 登录 → 看事件日志有条目 ✓
2. 再连一次同 MAC → 活跃设备 LastSeen 更新 ✓
3. /admin 添加码 → admin_action 有条目 ✓
4. 批量生成 10 码 → admin_action count=10 ✓
5. 触发邮箱限流 → login/rate_limited 条目 ✓
6. Dashboard 数字跟事件表核对 ✓
7. 导出 CSV 用 Excel 打开 ✓
8. 修改 `EVENT_LOG_RETENTION_DAYS=1`, 改容器时间手动调一天前的 mtime, restart, 旧事件被 prune 掉 ✓
   (或者就信 Prune 逻辑, 别搞时间戳)
9. 容器 restart, 事件日志从文件恢复 (如果启用了持久化) ✓

---

## 非目标 / 警示

- **不要**在 Go 代码里用 goroutines 大量并发写 JSONL — 单 mutex 保护整个 Append 就够, 不要 lock-free 或 channel 花活
- **不要**往事件里塞敏感数据: password / token / full code (只记后 4 位)
- **不要**让事件日志阻塞业务路径 — 写文件失败就 log.Printf 报错, 继续放行用户
- **不要**给已经实现的 guestCodes / denylist / ratelimit 重复造轮子, 复用它们的 snapshot / List API
- **活跃设备看板** 如果想精确到"真正在线", 后续可改调 iKuai API — 当前不做, 写在 TODO 里

---

## 不确定点 (需要实现前确认 / 快速查代码)

- `denylist.go` 里 Add/List/Remove 的确切签名是什么? 第一步 `git grep "func (.*denylist)"` 确认
- iKuai policy 存储的确切位置? 如果 admin 在 UI 改了 policy, audit 要记下 "field old→new", 得看 policy store 的 API
- admin.html 的 tab 结构: 新加 tab 得用现有 `.admin-tab` 和 `.admin-section` 类的 pattern, 看已有例子抄
