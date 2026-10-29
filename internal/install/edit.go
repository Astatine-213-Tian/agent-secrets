package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

// EditDone is the fixed success message for config set and unset.
const EditDone = "Configuration updated and read back; no values were printed. Restart the client if it does not reload settings."

var (
	ErrEditUsage       = errors.New("Usage: agent-secrets config set FILE KEY JSON_VALUE, or config unset FILE KEY. KEY is dot-separated (env.MCP_TOOL_TIMEOUT) or a JSON array of names; JSON_VALUE is JSON, such as '\"1800000\"' for a string.")
	ErrEditUnsupported = errors.New("Unsupported file: config set changes Claude Code settings.json, Codex config.toml, and Docker config.json. npm files are not edited; change ~/.claude.json with Claude Code's own commands, such as claude mcp remove NAME.")
	ErrEditCredential  = errors.New("Refused: the setting is or contains a credential; no values were printed.")
	ErrEditProtection  = errors.New("Refused: the edit would weaken credential protection (the agent-secrets hook, disableAllHooks, or sandbox.credentials); no values were printed.")
	ErrEdit            = errors.New("Cannot safely change configuration; the file may be malformed, missing the key, linked, or changed. No file contents were printed.")
)

// ConfigCommand applies one `config set` or `config unset` command line. The
// file never reaches the output: success and every failure are fixed messages.
func ConfigCommand(home, cwd string, args []string) error {
	remove := len(args) == 3 && args[0] == "unset"
	if !remove && (len(args) != 4 || args[0] != "set") {
		return ErrEditUsage
	}
	key, ok := parseKey(args[2])
	if !ok {
		return ErrEditUsage
	}
	var value any
	if !remove {
		d := json.NewDecoder(strings.NewReader(args[3]))
		d.UseNumber()
		var extra any
		if d.Decode(&value) != nil || d.Decode(&extra) != io.EOF {
			return ErrEditUsage
		}
	}
	path := args[1]
	if path == "~" || strings.HasPrefix(path, "~/") {
		path = home + path[1:]
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	return EditConfig(home, cwd, path, key, value, remove)
}

func parseKey(s string) ([]string, bool) {
	var key []string
	if strings.HasPrefix(s, "[") {
		if json.Unmarshal([]byte(s), &key) != nil {
			return nil, false
		}
	} else {
		key = strings.Split(s, ".")
	}
	return key, len(key) > 0 && !slices.Contains(key, "")
}

// EditConfig changes one non-credential member of a supported config.
// Like installation, it parses before writing, backs up privately, refuses a
// concurrent change, replaces atomically, and verifies by readback.
func EditConfig(home, cwd, path string, key []string, value any, remove bool) error {
	if !filepath.IsAbs(home) || home == "/" || !filepath.IsAbs(path) {
		return ErrEdit
	}
	path = filepath.Clean(path)
	if !Locations(home, cwd).Editable(path) {
		return ErrEditUnsupported
	}
	resolved, config, e := configFile(home, cwd, path)
	if e != nil {
		return ErrEdit
	}
	st, e := os.Lstat(resolved)
	if e != nil || !st.Mode().IsRegular() {
		return ErrEdit
	}
	before, e := readRegular(resolved, policy.MaxDocument)
	if e != nil {
		return ErrEdit
	}
	after, e := policy.Edit(config, before, key, value, remove)
	if errors.Is(e, policy.ErrCredentialSetting) {
		return ErrEditCredential
	}
	if e != nil {
		return ErrEdit
	}
	// An edit must not switch off the protection that allows it, or change
	// which credentials Claude Code's sandbox hides.
	if path == filepath.Join(home, ".claude/settings.json") {
		own := claudeCommand(filepath.Join(home, ".local/share/agent-secrets/agent-secrets"))
		sandbox := key[0] == "sandbox" && (len(key) == 1 || key[1] == "credentials")
		if key[0] == "disableAllHooks" || sandbox || hasHook(before, own) && !hasHook(after, own) {
			return ErrEditProtection
		}
	}
	backup := filepath.Join(home, ".local/share/agent-secrets/backups", fmt.Sprintf("%d", time.Now().UnixNano()), filepath.Base(path))
	if atomicWrite(backup, before, 0600) != nil {
		return ErrEdit
	}
	if now, e := readRegular(resolved, policy.MaxDocument); e != nil || !bytes.Equal(now, before) {
		return ErrEdit
	}
	if atomicWrite(resolved, after, st.Mode().Perm()) != nil {
		return ErrEdit
	}
	return nil
}
