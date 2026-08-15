package main

// cli.go
// Administrative subcommands that operate directly on the database.
//
// These are the second half of the break-glass story. The local account in
// localadmin.go recovers a portal whose SSO configuration is broken but whose
// admin console is still reachable; these recover one where it is not — a
// listener bound to the wrong address, a TLS certificate that will not load, or
// simply a deployment where no local account was ever created.
//
// They need shell access to the host, which is a meaningfully higher bar than
// an HTTP endpoint, and they never start the HTTP server. Both properties are
// the point: `wifi-portal config set` is the tool of last resort, and a tool of
// last resort should not depend on anything that might be what broke.

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
	"github.com/kazuhahub/wifi-portal/internal/secret"
	"github.com/kazuhahub/wifi-portal/internal/settings"
)

// cliUsage is printed for `wifi-portal help` and on a malformed invocation.
const cliUsage = `wifi-portal — iKuai captive-portal authentication gateway

Usage:
  wifi-portal                     Start the portal.
  wifi-portal init [dir]          Write .env and systemd unit templates.

Recovery and administration (operate directly on the database):

  wifi-portal config list                 Show every setting; secrets are masked.
  wifi-portal config get <section.key>    Show one setting.
  wifi-portal config set <section.key> <value>
                                          Change one setting. Takes effect on the
                                          next restart.
  wifi-portal config unset <section.key>  Reset one setting to its default.

  wifi-portal admin list                  List break-glass local accounts.
  wifi-portal admin add <username>        Create one, prompting for a password.
  wifi-portal admin passwd <username>     Change a password.
  wifi-portal admin delete <username>     Remove one.
  wifi-portal admin enable [cidr,...]     Turn on /admin/login/local, optionally
                                          restricted to the given networks.
  wifi-portal admin disable               Turn it off again.

These read the same bootstrap environment the portal does (SESSION_SECRET,
ENCRYPTION_KEY, DATA_DIR, DB_DSN), so run them with the same environment file.

Example — recovering from a wrong Entra tenant:
  wifi-portal config set oidc.tenant_id 00000000-1111-2222-3333-444444444444
`

// runCLI dispatches a subcommand. It returns false when args are not a
// subcommand, so main proceeds to start the portal.
func runCLI(args []string) (handled bool, exitCode int) {
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(cliUsage)
		return true, 0
	case "config":
		return true, runConfigCmd(args[1:])
	case "admin":
		return true, runAdminCmd(args[1:])
	}
	return false, 0
}

// openForCLI connects using the same bootstrap configuration the portal uses.
//
// It deliberately does not call loadBootstrap, which exits the process on a
// missing SESSION_SECRET — a secret these commands never need. Someone
// recovering a portal should not have to satisfy an unrelated requirement to
// read their own settings back.
func openForCLI() (*dbstore.DB, *settings.Store, error) {
	dataDir := envOr("DATA_DIR", "/data")
	dsn := strings.TrimSpace(envOr("DB_DSN", ""))
	db, err := dbstore.Open(dbstore.Options{DSN: dsn, DataDir: dataDir})
	if err != nil {
		return nil, nil, err
	}
	if err := dbstore.Migrate(db); err != nil {
		db.Close()
		return nil, nil, err
	}
	keyring := secret.NewKeyring(strings.TrimSpace(envOr("ENCRYPTION_KEY", "")))
	return db, settings.New(db, keyring, isSecretSetting), nil
}

func cliError(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "wifi-portal: "+format+"\n", args...)
	return 1
}

// splitSettingKey parses "section.key". Section names contain no dots, so the
// first one is the separator.
func splitSettingKey(s string) (section, key string, ok bool) {
	section, key, ok = strings.Cut(strings.TrimSpace(s), ".")
	if !ok || section == "" || key == "" {
		return "", "", false
	}
	return section, key, true
}

func runConfigCmd(args []string) int {
	if len(args) == 0 {
		fmt.Print(cliUsage)
		return 2
	}
	db, store, err := openForCLI()
	if err != nil {
		return cliError("cannot open the database: %v", err)
	}
	defer db.Close()

	switch args[0] {
	case "list":
		values, err := store.LoadAll()
		if err != nil {
			return cliError("reading settings: %v", err)
		}
		keys := make([]string, 0, len(settingRegistry))
		for _, d := range settingRegistry {
			keys = append(keys, settings.Key(d.Section, d.Key))
		}
		sort.Strings(keys)
		for _, k := range keys {
			d := settingIndex[k]
			v := values[k]
			if v == "" {
				v = d.Default
			}
			if d.Secret {
				// Masked, never printed: `config list` is the command someone
				// runs while sharing a terminal with a colleague.
				v = secret.Mask(v)
			}
			fmt.Printf("%-40s %s\n", k, v)
		}
		return 0

	case "get":
		if len(args) < 2 {
			return cliError("usage: config get <section.key>")
		}
		section, key, ok := splitSettingKey(args[1])
		if !ok {
			return cliError("expected section.key, got %q", args[1])
		}
		values, err := store.LoadAll()
		if err != nil {
			return cliError("reading settings: %v", err)
		}
		v := values[settings.Key(section, key)]
		if settingIndex[settings.Key(section, key)].Secret {
			v = secret.Mask(v)
		}
		fmt.Println(v)
		return 0

	case "set":
		if len(args) < 3 {
			return cliError("usage: config set <section.key> <value>")
		}
		section, key, ok := splitSettingKey(args[1])
		if !ok {
			return cliError("expected section.key, got %q", args[1])
		}
		if _, known := settingIndex[settings.Key(section, key)]; !known {
			// Refused rather than stored: an unknown key would sit in the table
			// doing nothing, and the operator would believe they had fixed
			// something. `config list` shows the valid names.
			return cliError("unknown setting %q — run `wifi-portal config list` for the valid names", args[1])
		}
		if err := store.SetOne(section, key, args[2], "cli"); err != nil {
			return cliError("saving: %v", err)
		}
		fmt.Printf("set %s.%s — restart the portal for it to take effect\n", section, key)
		return 0

	case "unset":
		if len(args) < 2 {
			return cliError("usage: config unset <section.key>")
		}
		section, key, ok := splitSettingKey(args[1])
		if !ok {
			return cliError("expected section.key, got %q", args[1])
		}
		d, known := settingIndex[settings.Key(section, key)]
		if !known {
			return cliError("unknown setting %q", args[1])
		}
		if err := store.SetOne(section, key, d.Default, "cli"); err != nil {
			return cliError("saving: %v", err)
		}
		fmt.Printf("reset %s.%s to its default (%q)\n", section, key, d.Default)
		return 0
	}
	fmt.Print(cliUsage)
	return 2
}

// promptPassword reads a password without echoing it, twice, and refuses a
// mismatch. Falls back to a visible read when stdin is not a terminal, which is
// how an automated provisioning script would use it.
func promptPassword() (string, error) {
	if !term.IsTerminal(int(syscall.Stdin)) {
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	fmt.Print("Password: ")
	first, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	fmt.Print("Repeat:   ")
	second, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("passwords do not match")
	}
	return string(first), nil
}

func runAdminCmd(args []string) int {
	if len(args) == 0 {
		fmt.Print(cliUsage)
		return 2
	}
	db, store, err := openForCLI()
	if err != nil {
		return cliError("cannot open the database: %v", err)
	}
	defer db.Close()

	switch args[0] {
	case "list":
		rows, err := listLocalAdmins(db)
		if err != nil {
			return cliError("reading accounts: %v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no local accounts (create one with `wifi-portal admin add <username>`)")
			return 0
		}
		for _, r := range rows {
			last := "never"
			if r.LastLoginAt != nil {
				last = r.LastLoginAt.Local().Format("2006-01-02 15:04")
			}
			state := "enabled"
			if !r.Enabled {
				state = "disabled"
			}
			locked := ""
			if r.LockedUntil != nil {
				locked = fmt.Sprintf(" locked-until=%s", r.LockedUntil.Local().Format("15:04"))
			}
			fmt.Printf("%-24s %-8s last-login=%s%s\n", r.Username, state, last, locked)
		}
		return 0

	case "add", "passwd":
		if len(args) < 2 {
			return cliError("usage: admin %s <username>", args[0])
		}
		password, err := promptPassword()
		if err != nil {
			return cliError("%v", err)
		}
		if err := createLocalAdmin(db, args[1], password); err != nil {
			return cliError("%v", err)
		}
		fmt.Printf("account %q saved\n", strings.ToLower(args[1]))
		// Saying so unprompted, because creating an account that cannot be used
		// is the obvious way to be surprised here.
		values, _ := store.LoadAll()
		if !values.Bool(secLocalAdmin, "enabled", false) {
			fmt.Println("note: local login is currently disabled — run `wifi-portal admin enable` to turn it on")
		}
		return 0

	case "delete":
		if len(args) < 2 {
			return cliError("usage: admin delete <username>")
		}
		removed, err := deleteLocalAdmin(db, args[1])
		if err != nil {
			return cliError("%v", err)
		}
		if !removed {
			return cliError("no such account: %s", args[1])
		}
		fmt.Printf("account %q removed\n", strings.ToLower(args[1]))
		return 0

	case "enable":
		allowed := ""
		if len(args) > 1 {
			allowed = args[1]
			// Validated here rather than at request time: a typo would otherwise
			// turn into a 404 on the login page during the outage it exists for.
			if _, err := localAdminAllowedFrom(allowed); err != nil {
				return cliError("%v", err)
			}
		}
		if err := store.Save(secLocalAdmin, map[string]string{
			"enabled":      "true",
			"allowed_from": allowed,
		}, "cli"); err != nil {
			return cliError("saving: %v", err)
		}
		where := "any address"
		if allowed != "" {
			where = allowed
		}
		fmt.Printf("local login enabled at /admin/login/local, reachable from %s\n", where)
		fmt.Println("restart the portal for it to take effect")
		return 0

	case "disable":
		if err := store.SetOne(secLocalAdmin, "enabled", "false", "cli"); err != nil {
			return cliError("saving: %v", err)
		}
		fmt.Println("local login disabled — restart the portal for it to take effect")
		return 0
	}
	fmt.Print(cliUsage)
	return 2
}
