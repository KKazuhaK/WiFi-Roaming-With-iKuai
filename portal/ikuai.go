package main

// ikuai.go
// iKuai 自定义认证协议的两端:
//   (a) 入: extractDeviceInfo - 从 iKuai 路由器 302 过来的 query 里扒出设备 IP 和 MAC
//   (b) 出: buildWebAuthURL   - 生成放行 URL (含 MD5 token)，302 浏览器到 iKuai 云
//
// 依据: iKuai 官方自定义认证对接文档
// https://www.ikuai8.com/index.php?option=com_content&view=article&id=774
//
// 文档里 token 公式 (MD5):
//   md5("user_ip={ip}&timestamp={ts}&mac={mac}&upload=0&download=0&key={appkey}")
// 放行 URL:
//   https://portal.ikuai8-wifi.com/Action/webauth-up
//     ?type=20&user_ip={ip}&timestamp={ts}&mac={mac}&upload=0&download=0&token={hex}
//
// 注意:
//   - iKuai 不同固件版本 query 字段名不完全一样 (user_ip vs ip, user_mac vs mac 等)
//     所以 IN 这一侧用 firstNonEmpty 兼容多种
//   - 这里用 MD5 不是做安全哈希, 是 iKuai 指定的协议本身要求
//     我们这条链路的安全是靠 appkey 的机密性保证的

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// iKuai 云上放行接口的固定地址。写死, 不走环境变量。
const ikuaiWebAuthEndpoint = "https://portal.ikuai8-wifi.com/Action/webauth-up"

// DeviceInfo 是我们从 iKuai 那边拿到的上网设备信息。
type DeviceInfo struct {
	IP  string
	MAC string
}

// extractDeviceInfo 从 iKuai 302 过来的 /portal 请求里解析设备信息。
// 支持多种字段名以兼容不同固件版本。
// 返回 ok=false 表示没法确定设备身份, 上层应拒绝进入登录流程。
func extractDeviceInfo(r *http.Request, cfg Config) (DeviceInfo, bool) {
	q := r.URL.Query()
	ip := firstNonEmpty(q, cfg.IKuaiIPKeys)
	mac := firstNonEmpty(q, cfg.IKuaiMACKeys)

	// MAC 常见被 URL 编码成 %3A, net/url 会自动解码。再做一次规范化。
	mac = normalizeMAC(mac)

	if ip == "" || mac == "" {
		return DeviceInfo{}, false
	}
	return DeviceInfo{IP: ip, MAC: mac}, true
}

// buildWebAuthURL 生成给浏览器 302 过去的 iKuai 放行 URL。
func buildWebAuthURL(cfg Config, dev DeviceInfo) string {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// token 源串必须完全按 iKuai 规定的顺序和格式拼接
	raw := fmt.Sprintf(
		"user_ip=%s&timestamp=%s&mac=%s&upload=0&download=0&key=%s",
		dev.IP, timestamp, dev.MAC, cfg.IKuaiAppKey,
	)
	sum := md5.Sum([]byte(raw))
	token := hex.EncodeToString(sum[:])

	// 构造最终 URL
	params := url.Values{}
	params.Set("type", "20") // 20 = web 认证
	params.Set("user_ip", dev.IP)
	params.Set("timestamp", timestamp)
	params.Set("mac", dev.MAC)
	params.Set("upload", "0")   // 上行限速, 0 = 不限
	params.Set("download", "0") // 下行限速, 0 = 不限
	params.Set("token", token)

	return ikuaiWebAuthEndpoint + "?" + params.Encode()
}

// --- helpers ---

// firstNonEmpty 从 query 里按备选字段名找出第一个非空值。
func firstNonEmpty(q url.Values, keys []string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

// normalizeMAC 把 MAC 统一成小写冒号分隔格式 (aa:bb:cc:dd:ee:ff)。
// iKuai 有时发过来是 AA-BB-CC-DD-EE-FF, 有时是 aabbccddeeff, 统一一下安全。
func normalizeMAC(mac string) string {
	if mac == "" {
		return ""
	}
	// 去除常见分隔符
	clean := strings.Map(func(r rune) rune {
		switch r {
		case '-', ':', ' ':
			return -1
		}
		return r
	}, mac)
	clean = strings.ToLower(clean)
	// 如果长度不是 12 (6 字节 hex), 原样返回, 让 iKuai 自己报错
	if len(clean) != 12 {
		return strings.ToLower(mac)
	}
	// 按 2 字符插冒号
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(clean[i : i+2])
	}
	return b.String()
}
