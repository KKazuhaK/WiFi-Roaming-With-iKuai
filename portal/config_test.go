package main

import "testing"

// TestSanitizeBrandColor: BRAND_COLOR env 进 <style>--brand: X;</style>.
// html/template CSS 上下文转义不挡 CSS 语法逃逸 (如 "red; } body { display: none } /*"),
// 必须在入口校验. 不抛错, 只静默回退到 fallback — admin 改坏 brand 颜色不该让进程崩.
func TestSanitizeBrandColor(t *testing.T) {
	const fallback = "#2563eb"
	cases := []struct {
		in   string
		want string
	}{
		// 合法 hex
		{"#fff", "#fff"},
		{"#FFF", "#FFF"},
		{"#abcdef", "#abcdef"},
		{"#ABCDEF", "#ABCDEF"},
		{"#12345678", "#12345678"}, // #RRGGBBAA
		// 空 / 空白 → fallback
		{"", fallback},
		{"   ", fallback},
		// 非法 → fallback
		{"red", fallback},
		{"#xyz", fallback},
		{"#12", fallback},     // 长度不对
		{"#12345", fallback},  // 长度不对
		{"#123456789", fallback},
		// 攻击载荷
		{"red; } body { display: none } /*", fallback},
		{"#fff; background: url(http://evil)", fallback},
		{"javascript:alert(1)", fallback},
		{"#fff\n; @import url(x)", fallback},
	}
	for _, c := range cases {
		got := sanitizeBrandColor(c.in, fallback)
		if got != c.want {
			t.Errorf("sanitizeBrandColor(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
