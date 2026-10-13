package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"github.com/BurntSushi/toml"
)

const maxConfigInput = 4 << 20

var ErrConfigView = errors.New("Cannot safely display configuration; no configuration values or error details were printed.")

// ReadCodexConfig runs an allowlisted reader with already-sanitized stdin.
// The original file path never reaches the reader, and no shell is invoked.
func ReadCodexConfig(ctx context.Context, home, reader string, args []string) ([]byte, error) {
	program, ok := policy.ConfigReadFilter(reader, args)
	if !ok {
		return nil, ErrConfigView
	}
	data, err := CodexConfigView(home)
	if err != nil {
		return nil, err
	}
	c := exec.CommandContext(ctx, program, args...)
	c.Stdin = bytes.NewReader(data)
	c.Stderr = io.Discard
	out, err := c.Output()
	if err != nil {
		return nil, ErrConfigView
	}
	return out, nil
}

// CodexConfigView reads only the conventional user config and returns a fully
// sanitized TOML document. It never executes commands, expands environment
// references, writes files, or reads another credential store.
func CodexConfigView(home string) ([]byte, error) {
	if !filepath.IsAbs(home) || home == "/" {
		return nil, ErrConfigView
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, ErrConfigView
	}
	defer root.Close()
	st, err := root.Lstat(".codex")
	if err != nil || !st.IsDir() {
		return nil, ErrConfigView
	}
	dir, err := root.OpenRoot(".codex")
	if err != nil {
		return nil, ErrConfigView
	}
	defer dir.Close()
	openedDir, err := dir.Stat(".")
	if err != nil || !os.SameFile(st, openedDir) {
		return nil, ErrConfigView
	}
	before, err := dir.Lstat("config.toml")
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxConfigInput {
		return nil, ErrConfigView
	}
	// Root may resolve symlinks itself, so use Lstat and identity readback as
	// well as O_NOFOLLOW. O_NONBLOCK avoids hanging if replaced with a FIFO.
	f, err := dir.OpenFile("config.toml", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrConfigView
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() || !os.SameFile(before, st) || st.Size() > maxConfigInput {
		return nil, ErrConfigView
	}
	return RedactCodexConfig(f)
}

// RedactCodexConfig parses before redacting, so dotted/quoted keys, inline
// tables, escapes, and multiline strings have the same policy. It buffers all
// output and discards parser diagnostics, comments, and original formatting.
func RedactCodexConfig(input io.Reader) (output []byte, err error) {
	defer func() {
		if recover() != nil {
			output, err = nil, ErrConfigView
		}
	}()
	data, err := io.ReadAll(io.LimitReader(input, maxConfigInput+1))
	if err != nil || len(data) > maxConfigInput {
		return nil, ErrConfigView
	}
	var config map[string]any
	if toml.Unmarshal(data, &config) != nil {
		return nil, ErrConfigView
	}
	clean, err := redactConfig(config, nil)
	if err != nil {
		return nil, ErrConfigView
	}
	var buf bytes.Buffer
	if toml.NewEncoder(&buf).Encode(clean) != nil {
		return nil, ErrConfigView
	}
	return buf.Bytes(), nil
}

func redactConfig(value any, path []string) (any, error) {
	if len(path) > 64 {
		return nil, ErrConfigView
	}
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			clean, err := redactConfig(item, append(path, key))
			if err != nil {
				return nil, err
			}
			out[key] = clean
		}
		return out, nil
	case []map[string]any:
		out := make([]any, len(v))
		for i, item := range v {
			clean, err := redactConfig(item, append(path, ""))
			if err != nil {
				return nil, err
			}
			out[i] = clean
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			clean, err := redactConfig(item, append(path, ""))
			if err != nil {
				return nil, err
			}
			out[i] = clean
		}
		return out, nil
	default:
		if policy.VisibleCodexValue(path, v) {
			return v, nil
		}
		return policy.Redacted, nil
	}
}
