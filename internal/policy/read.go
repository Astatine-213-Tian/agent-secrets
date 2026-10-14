package policy

import (
	"regexp"
	"strings"
)

var readCount = regexp.MustCompile(`^[+]?[0-9]{1,9}$`)
var sedPrint = regexp.MustCompile(`^(?:[1-9][0-9]{0,8}|\$)(?:,(?:[1-9][0-9]{0,8}|\$))?p$`)

// ConfigReadFilter accepts only readers that consume sanitized stdin without
// opening additional files, executing programs, writing files, or following logs.
// Both the hook and its private runner validate this contract independently.
func ConfigReadFilter(reader string, args []string) (string, bool) {
	switch reader {
	case "cat":
		for _, arg := range args {
			if len(arg) < 2 || arg[0] != '-' || strings.Trim(arg[1:], "nbsvet") != "" {
				return "", false
			}
		}
		return "/bin/cat", true
	case "head", "tail":
		valid := len(args) == 0
		if len(args) == 2 && (args[0] == "-n" || args[0] == "-c") {
			valid = readCount.MatchString(args[1])
		}
		if len(args) == 1 && strings.HasPrefix(args[0], "-") {
			n := args[0][1:]
			if strings.HasPrefix(n, "n") || strings.HasPrefix(n, "c") {
				n = n[1:]
			}
			valid = readCount.MatchString(n)
		}
		return "/usr/bin/" + reader, valid
	case "sed":
		if len(args) == 3 && args[0] == "-n" && args[1] == "-e" {
			args = []string{args[0], args[2]}
		}
		return "/usr/bin/sed", len(args) == 2 && args[0] == "-n" && sedPrint.MatchString(args[1])
	}
	return "", false
}
