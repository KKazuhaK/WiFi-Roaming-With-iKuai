package main

// active_devices.go
// 内存里维护"最近放行过的设备"映射, 给 /admin 面板看活跃设备用.
// 不接 iKuai, 精度有限 (断线 / 主动登出不反映), 但够 admin 巡检.
//
// 语义:
//   - 每次成功放行时 Track(mac, ...) 更新.
//   - gcLoop 每 15 分钟扫一次, 超过 window 没活动的踢掉.
//   - 不持久化 (重启清零, 数据随使用自然重建).

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type ActiveDevice struct {
	MAC       string    `json:"mac"`
	UserID    string    `json:"user_id"` // upn 或 guest-xxx
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type ActiveDevices struct {
	mu      sync.Mutex
	devices map[string]*ActiveDevice // key = normalized MAC
	window  time.Duration
}

func newActiveDevices(window time.Duration) *ActiveDevices {
	return &ActiveDevices{
		devices: make(map[string]*ActiveDevice),
		window:  window,
	}
}

// Track 记录一次放行. userID 是 upn / guest-xxx.
func (a *ActiveDevices) Track(mac, userID, ip, method string) {
	norm := normalizeMAC(mac)
	if norm == "" {
		return
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if d, ok := a.devices[norm]; ok {
		d.LastSeen = now
		if userID != "" {
			d.UserID = userID
		}
		if ip != "" {
			d.IP = ip
		}
		if method != "" {
			d.Method = method
		}
		return
	}
	a.devices[norm] = &ActiveDevice{
		MAC:       norm,
		UserID:    userID,
		IP:        ip,
		Method:    method,
		FirstSeen: now,
		LastSeen:  now,
	}
}

// Remove 删一条 (admin 手动踢出). 返回是否真的删到.
func (a *ActiveDevices) Remove(mac string) bool {
	norm := normalizeMAC(mac)
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.devices[norm]; !ok {
		return false
	}
	delete(a.devices, norm)
	return true
}

// List 返回按 LastSeen 倒序的设备副本.
func (a *ActiveDevices) List() []ActiveDevice {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ActiveDevice, 0, len(a.devices))
	for _, d := range a.devices {
		out = append(out, *d)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return strings.Compare(out[i].MAC, out[j].MAC) < 0
	})
	return out
}

// Count 返回当前活跃 (非过期) 设备数.
func (a *ActiveDevices) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.devices)
}

// prune 删掉超过 window 没活动的条目.
func (a *ActiveDevices) prune() int {
	if a.window <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-a.window)
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for mac, d := range a.devices {
		if d.LastSeen.Before(cutoff) {
			delete(a.devices, mac)
			n++
		}
	}
	return n
}

// gcLoop 每 15 分钟扫一次 prune. 阻塞调用, 放 goroutine 里跑.
func (a *ActiveDevices) gcLoop() {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for range t.C {
		a.prune()
	}
}
