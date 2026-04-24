package main

// i18n.go
// 三语字符串表 + 语言判定. 字符串本体在 portal/i18n/<lang>.json,
// 启动时 go:embed 烤进二进制, 单例 map 缓存. 模板里通过 T 函数查询,
// JS 通过 jsonI18N 注入命名空间子集.
//
// 设计取舍:
//   - 不做 type-safe struct: 字段太多会臃肿, 且现在 admin 那边量级 ~150 条
//   - 启动期校验所有 lang 必须有所有 key (以 EN 为基准), 缺则 fatal — 把
//     "type-safe struct 的编译期保证" 退化成"启动期保证"
//   - 缺 key 运行时 fallback: 当前 lang → EN → key 字面量 (便于定位)
//   - 不引入复数 / 复杂格式化, 用 fmt.Sprintf 套 %s/%d 就够了

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
	"strings"
)

//go:embed i18n/*.json
var i18nFS embed.FS

type Lang string

const (
	LangZHCN Lang = "zh-cn"
	LangZHTW Lang = "zh-tw"
	LangEN   Lang = "en"
)

// supportedLangs: 启动校验时遍历用. 加新语言只改这一行 + 新加 json 文件.
var supportedLangs = []Lang{LangZHCN, LangZHTW, LangEN}

// translations[lang][key] = value. 启动后只读, 多 goroutine 并发安全.
var translations map[Lang]map[string]string

// loadTranslations: 启动时读所有 i18n/*.json + 校验. 任一失败 fatal.
// 在 loadConfig 之后、handler 注册之前调用.
func loadTranslations() {
	translations = make(map[Lang]map[string]string, len(supportedLangs))
	for _, l := range supportedLangs {
		path := fmt.Sprintf("i18n/%s.json", l)
		data, err := i18nFS.ReadFile(path)
		if err != nil {
			log.Fatalf("i18n: 读取 %s 失败: %v", path, err)
		}
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			log.Fatalf("i18n: 解析 %s 失败: %v", path, err)
		}
		translations[l] = m
	}
	// 校验: 以 EN 为 source-of-truth, 其它 lang 必须有所有 key.
	base := translations[LangEN]
	if base == nil {
		log.Fatalf("i18n: en.json 加载失败")
	}
	missing := map[Lang][]string{}
	for _, l := range supportedLangs {
		if l == LangEN {
			continue
		}
		for k := range base {
			if _, ok := translations[l][k]; !ok {
				missing[l] = append(missing[l], k)
			}
		}
	}
	if len(missing) > 0 {
		for l, keys := range missing {
			sort.Strings(keys)
			log.Printf("i18n: lang %s 缺 %d 个 key: %v", l, len(keys), keys)
		}
		log.Fatalf("i18n: 翻译不完整, 见上面 缺失列表")
	}
	log.Printf("i18n: 已加载 %d 种语言, 每种 %d 条", len(supportedLangs), len(base))
}

// T: 按 lang 查 key. 找不到 → fallback 到 EN. 还找不到 → 返回 key 字面量
// (生产环境如果出现这种情况, key 会原样显示在页面上, 一眼能定位忘加翻译的地方).
// 有 args 时套 fmt.Sprintf, 字符串里用 %s/%d 占位.
func T(lang Lang, key string, args ...any) string {
	s, ok := translations[lang][key]
	if !ok {
		s, ok = translations[LangEN][key]
		if !ok {
			return key
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// jsonI18N: 给前端 JS 用. 返回所有以 prefix 开头的 key=value 的 JSON
// 字符串 (key 去掉 prefix 缩短). 注入方式:
//   <script>window.__I18N = {{ jsonI18N .Lang "admin." }};</script>
// 然后 JS: __I18N["toast.added"] / __I18N["btn.delete"].
// 返回 template.JS 而非 string, 让 html/template 不再做转义 (返回值已经是
// 合法 JSON 文本, 可直接当 JS 表达式).
func jsonI18N(lang Lang, prefix string) (template.JS, error) {
	src := translations[lang]
	if src == nil {
		src = translations[LangEN]
	}
	sub := make(map[string]string, len(src))
	for k, v := range src {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		sub[strings.TrimPrefix(k, prefix)] = v
	}
	data, err := json.Marshal(sub)
	if err != nil {
		return "", err
	}
	return template.JS(data), nil
}

// pickLang: query > Accept-Language > LangEN (fallback).
func pickLang(r *http.Request) Lang {
	if q := r.URL.Query().Get("lang"); q != "" {
		if l, ok := parseLang(q); ok {
			return l
		}
	}
	al := r.Header.Get("Accept-Language")
	if al != "" {
		for _, part := range strings.Split(al, ",") {
			tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
			if l, ok := parseLang(tag); ok {
				return l
			}
		}
	}
	return LangEN
}

func parseLang(raw string) (Lang, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.HasPrefix(s, "zh-tw"),
		strings.HasPrefix(s, "zh-hk"),
		strings.HasPrefix(s, "zh-mo"),
		strings.HasPrefix(s, "zh-hant"):
		return LangZHTW, true
	case strings.HasPrefix(s, "zh"):
		return LangZHCN, true
	case strings.HasPrefix(s, "en"):
		return LangEN, true
	}
	return "", false
}
