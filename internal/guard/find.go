package guard

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Inspect explicit actions as commands. Bulk content readers over find's
// computed results can include protected files; metadata actions remain native.
func (g checker) findActionBlocked(args []*syntax.Word, source string, depth int) bool {
	for i := 0; i < len(args); i++ {
		flag, _, _ := literalWord(args[i].Parts, false)
		switch flag {
		case "-exec", "-execdir", "-ok", "-okdir":
		default:
			continue
		}
		start := i + 1
		for i = start; i < len(args); i++ {
			v, _, _ := literalWord(args[i].Parts, false)
			if v == ";" || v == "+" {
				break
			}
		}
		if i == start {
			continue
		}
		words := args[start:i]
		command := source[words[0].Pos().Offset():words[len(words)-1].End().Offset()]
		if g.inspectCode(command, depth+1) {
			return true
		}
		call := commandArgs(words)
		if len(call) == 0 {
			continue
		}
		name, _, _ := literalWord(call[0].Parts, false)
		switch filepath.Base(name) {
		case "cat", "head", "tail", "sed", "awk", "rg", "grep", "cp", "mv", "tar", "zip", "curl":
			if strings.Contains(command, "{}") {
				return true
			}
		}
	}
	return false
}
