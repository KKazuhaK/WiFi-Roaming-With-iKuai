package main

// admin_settings.go
// The admin API behind the Settings pages.
//
// One pair of endpoints for every section rather than one per field:
//
//	GET  /admin/api/settings/{section}
//	POST /admin/api/settings/{section}
//
// A settings page is submitted as a unit and the store saves it transactionally,
// so half-applied OIDC credentials — new tenant, old client secret — is a state
// no operator asked for and one that breaks sign-in until someone notices.
//
// Credentials never travel back to the browser. A GET returns the non-secret
// fields plus a `present` map saying which secrets are set, which is all a form
// needs to render "leave blank to keep the current value"; a POST with a blank
// secret means unchanged. That convention lives in the settings store so both
// halves cannot drift.

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// settingsSectionResponse is what the Settings pages render from.
type settingsSectionResponse struct {
	Section string `json:"section"`
	// Fields holds every non-secret value in the section.
	Fields map[string]string `json:"fields"`
	// SecretsPresent reports, per secret key, whether one is stored. The value
	// itself is never included.
	SecretsPresent map[string]bool `json:"secretsPresent"`
	// Keys describes the section's schema so the UI can render a section it was
	// not specifically written for, and so a newly added setting shows up
	// without a frontend change.
	Keys []settingKeyInfo `json:"keys"`
	// Problems are validation findings against the configuration as a whole, so
	// the page can show "Duo is half-configured" next to the fields that cause
	// it rather than only in a log.
	Problems []settingProblem `json:"problems"`
}

type settingKeyInfo struct {
	Key     string `json:"key"`
	Secret  bool   `json:"secret"`
	Default string `json:"default"`
	// LegacyEnv is the environment variable this setting used to be read from.
	// Shown in the UI so an operator migrating from .env can find the field that
	// replaced the variable they know.
	LegacyEnv string `json:"legacyEnv,omitempty"`
}

type settingProblem struct {
	Section string `json:"section"`
	Key     string `json:"key,omitempty"`
	Message string `json:"message"`
	Fatal   bool   `json:"fatal"`
}

func toSettingProblems(in []ConfigProblem) []settingProblem {
	out := make([]settingProblem, 0, len(in))
	for _, p := range in {
		out = append(out, settingProblem{Section: p.Section, Key: p.Key, Message: p.Message, Fatal: p.Fatal})
	}
	return out
}

// sectionKeys returns a section's schema in registry order.
func sectionKeys(section string) []settingKeyInfo {
	out := make([]settingKeyInfo, 0, 8)
	for _, d := range settingRegistry {
		if d.Section != section {
			continue
		}
		out = append(out, settingKeyInfo{
			Key: d.Key, Secret: d.Secret, Default: d.Default, LegacyEnv: d.Env,
		})
	}
	return out
}

// knownSections lists every section that has at least one setting.
func knownSections() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range settingRegistry {
		if !seen[d.Section] {
			seen[d.Section] = true
			out = append(out, d.Section)
		}
	}
	sort.Strings(out)
	return out
}

// handleAdminSettings serves both verbs for /admin/api/settings/{section}.
func (a *App) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	// apiMode even for GET: without it an expired cookie answers 302 to the
	// login page, which fetch follows transparently and the panel then parses
	// as settings.
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}

	section := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/api/settings/"), "/")
	if section == "" {
		a.writeSettingsIndex(w)
		return
	}
	if len(sectionKeys(section)) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_section"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		a.getSettingsSection(w, section)
	case http.MethodPost:
		a.saveSettingsSection(w, r, section, admin.UPN)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	}
}

// writeSettingsIndex lists the sections, so the UI can build its navigation from
// the server's schema rather than a hardcoded copy that drifts.
func (a *App) writeSettingsIndex(w http.ResponseWriter) {
	sections := knownSections()
	out := make([]map[string]any, 0, len(sections))
	for _, s := range sections {
		out = append(out, map[string]any{"section": s, "keys": sectionKeys(s)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sections": out})
}

func (a *App) getSettingsSection(w http.ResponseWriter, section string) {
	stored, err := a.settings.LoadSection(section)
	if err != nil {
		log.Printf("admin settings: loading %s failed: %v", section, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load_failed"})
		return
	}
	// Fill in defaults so a never-saved section renders populated rather than
	// blank, matching what the portal is actually running with.
	for _, k := range sectionKeys(section) {
		if _, ok := stored[k.Key]; !ok {
			stored[k.Key] = k.Default
		}
	}
	fields, present := a.settings.Redact(section, stored)

	cfg := a.conf()
	all := validateRuntimeConfig(cfg)
	mine := make([]ConfigProblem, 0, len(all))
	for _, p := range all {
		if p.Section == section {
			mine = append(mine, p)
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, settingsSectionResponse{
		Section:        section,
		Fields:         fields,
		SecretsPresent: present,
		Keys:           sectionKeys(section),
		Problems:       toSettingProblems(mine),
	})
}

// saveSettingsSection writes a section and reloads the runtime.
//
// The body is JSON rather than form-encoded, unlike the older admin endpoints.
// Those predate this file and their url-encoded shape was not worth churning;
// a settings form, though, submits a variable set of keys whose names come from
// the server's own schema, and encoding that as a flat form would mean the
// handler could not tell an omitted key from an empty one — which is exactly the
// distinction the blank-means-unchanged rule for secrets depends on.
func (a *App) saveSettingsSection(w http.ResponseWriter, r *http.Request, section, updatedBy string) {
	var submitted map[string]string
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&submitted); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}

	// Drop keys the section does not define. A settings page must not become a
	// way to write arbitrary rows into the table.
	allowed := map[string]bool{}
	for _, k := range sectionKeys(section) {
		allowed[k.Key] = true
	}
	filtered := make(map[string]string, len(submitted))
	for k, v := range submitted {
		if allowed[k] {
			filtered[k] = v
		}
	}
	if len(filtered) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no_known_fields"})
		return
	}

	stored, err := a.settings.LoadSection(section)
	if err != nil {
		log.Printf("admin settings: loading %s before save failed: %v", section, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load_failed"})
		return
	}
	merged := a.settings.ApplySecretUpdates(section, stored, filtered)

	if err := a.settings.Save(section, merged, updatedBy); err != nil {
		log.Printf("admin settings: saving %s failed: %v", section, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "save_failed"})
		return
	}

	// Audit before the reload, so a save whose reload then fails is still on
	// record — that combination is exactly what an operator would need to see.
	changed := make([]string, 0, len(filtered))
	for k := range filtered {
		changed = append(changed, k)
	}
	sort.Strings(changed)
	a.logAdminAction(updatedBy, clientIP(r), ResultSuccess,
		"settings save section="+section+" keys="+strings.Join(changed, ","))

	// Apply immediately. Requiring a restart to change a brand colour would be a
	// poor trade, and for the OIDC section the reload is what tells the operator
	// whether the credentials they just typed actually work.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	reloadErr := a.reloadRuntime(ctx)

	resp := map[string]any{
		"ok":       true,
		"problems": toSettingProblems(validateRuntimeConfig(a.conf())),
	}
	if reloadErr != nil {
		// Not an HTTP error: the values were saved, and reporting a 500 would
		// have the operator believe their edit was lost and retype it.
		resp["warning"] = reloadErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}
