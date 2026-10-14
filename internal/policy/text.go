package policy

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

var privateBlock = regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)`)
var providerToken = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|dckr_pat_[A-Za-z0-9_-]{20,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,})\b`)
var bearerValue = regexp.MustCompile(`(?i)\b(Bearer|Basic)[ \t]+[A-Za-z0-9_+/.=~-]+`)
var urlText = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s<>"']+`)
var assignmentText = regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_.-]*)(\s*(?:=|:)\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|"[^\r\n]*|'[^\r\n]*|[^\s,;]+)`)
var flagText = regexp.MustCompile(`(--[A-Za-z][A-Za-z0-9_-]*)([ \t]+)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|"[^\r\n]*|'[^\r\n]*|[^\s;]+)`)
var headerText = regexp.MustCompile(`(?im)\b(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Registry-Auth|X-Auth|X-API-Key|X-Auth-Token|X-Access-Token)(\s*:\s*)([^\r\n"']+)`)
var basicArgument = regexp.MustCompile(`(?:--user|-u)([ \t]+)("[^"\r\n]*:[^"\r\n]*"|'[^'\r\n]*:[^'\r\n]*'|[^\s:]+:[^\s]+)`)

// SanitizeText removes recognized credential spans, not arbitrary high-entropy
// strings. Unknown prose, executable names and noncredential arguments survive.
func SanitizeText(s string) string {
	s = privateBlock.ReplaceAllString(s, Redacted)
	s = providerToken.ReplaceAllString(s, Redacted)
	s = urlText.ReplaceAllStringFunc(s, sanitizeURL)
	s = headerText.ReplaceAllStringFunc(s, func(v string) string { m := headerText.FindStringSubmatch(v); return m[1] + m[2] + Redacted })
	s = bearerValue.ReplaceAllStringFunc(s, func(v string) string {
		p := strings.IndexAny(v, " \t")
		value := strings.TrimSpace(v[p:])
		if strings.EqualFold(v[:p], "Basic") {
			b, e := base64.StdEncoding.DecodeString(value)
			if e != nil || !strings.Contains(string(b), ":") {
				return v
			}
		} else {
			switch strings.ToLower(value) {
			case "token", "tokens", "authentication", "authorization", "credentials":
				return v
			}
			if len(value) < 8 {
				return v
			}
		}
		return v[:p] + " " + Redacted
	})
	s = assignmentText.ReplaceAllStringFunc(s, func(v string) string {
		m := assignmentText.FindStringSubmatch(v)
		if SecretName(m[1]) {
			return m[1] + m[2] + Redacted
		}
		return v
	})
	s = flagText.ReplaceAllStringFunc(s, func(v string) string {
		m := flagText.FindStringSubmatch(v)
		if SecretName(strings.TrimPrefix(m[1], "--")) {
			return m[1] + m[2] + Redacted
		}
		return v
	})
	s = basicArgument.ReplaceAllStringFunc(s, func(v string) string { i := strings.IndexAny(v, " \t"); return v[:i] + " " + Redacted })
	return s
}

func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return Redacted
	}
	changed := false
	if u.User != nil {
		u.User = url.User(Redacted)
		changed = true
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Redacted
	}
	for key, values := range q {
		if SensitiveQuery(key) {
			for i := range values {
				values[i] = Redacted
			}
			q[key] = values
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	host := strings.ToLower(u.Hostname())
	if (host == "hooks.slack.com" && strings.HasPrefix(u.Path, "/services/")) || ((host == "discord.com" || host == "discordapp.com") && strings.Contains(u.Path, "/api/webhooks/")) {
		u.Path = "/" + Redacted
		u.RawPath = ""
		changed = true
	}
	if strings.Contains(u.Fragment, "=") {
		fragment, e := url.ParseQuery(u.Fragment)
		if e != nil {
			return Redacted
		}
		hidden := false
		for key, values := range fragment {
			if SensitiveQuery(key) {
				for i := range values {
					values[i] = Redacted
				}
				fragment[key] = values
				hidden = true
			}
		}
		if hidden {
			u.Fragment = fragment.Encode()
			u.RawFragment = ""
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return u.String()
}
