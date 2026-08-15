package main

// i18n.go
// Trilingual string table and language detection. Strings live in portal/i18n/<lang>.json,
// are embedded into the binary at build time, and cached in a singleton map. Go code queries via T;
// the React bundle imports the same JSON files directly (web-react/src/lib/i18n.ts) and reimplements
// T's lookup and %s/%d substitution, so there is still exactly one copy of every string.
//
// Tradeoffs:
//   - No type-safe struct: there are many fields, and admin already has around 150 strings.
//   - Startup validates that every language has every EN key; missing keys are fatal. This replaces
//     compile-time struct guarantees with startup guarantees.
//   - Runtime fallback for missing keys is current lang -> EN -> literal key for easy diagnosis.
//   - No pluralization or complex formatting; fmt.Sprintf with %s/%d is enough.

import (
	"embed"
	"encoding/json"
	"fmt"
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

// supportedLangs is used during startup validation. Add a language here and add its JSON file.
var supportedLangs = []Lang{LangZHCN, LangZHTW, LangEN}

// translations[lang][key] = value. Read-only after startup and safe for concurrent goroutines.
var translations map[Lang]map[string]string

// loadTranslations reads and validates all i18n/*.json files at startup. Any failure is fatal.
// Call after loadConfig and before handler registration.
func loadTranslations() {
	translations = make(map[Lang]map[string]string, len(supportedLangs))
	for _, l := range supportedLangs {
		path := fmt.Sprintf("i18n/%s.json", l)
		data, err := i18nFS.ReadFile(path)
		if err != nil {
			log.Fatalf("i18n: read %s failed: %v", path, err)
		}
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			log.Fatalf("i18n: parse %s failed: %v", path, err)
		}
		translations[l] = m
	}
	// Validate: EN is the source of truth; every other language must contain every key.
	base := translations[LangEN]
	if base == nil {
		log.Fatalf("i18n: en.json failed to load")
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
			log.Printf("i18n: lang %s missing %d keys: %v", l, len(keys), keys)
		}
		log.Fatalf("i18n: translations incomplete, see missing keys above")
	}
	log.Printf("i18n: loaded %d langs, %d keys each", len(supportedLangs), len(base))
}

// T looks up key for lang. Missing keys fall back to EN, then to the literal key so missing
// translations are visible in production. Args are formatted with fmt.Sprintf using %s/%d.
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
