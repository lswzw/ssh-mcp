// Package redact removes common secret forms before remote output is returned
// to an AI client or stored in local audit records.
package redact

import (
	"regexp"
	"strings"
)

const Marker = "[REDACTED]"

type TextResult struct {
	Value    string
	Redacted bool
}

var (
	privateKeyPattern    = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	connectionURLPattern = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^:\s/]+:)[^@\s/]+@`)
	secretLinePattern    = regexp.MustCompile(`(?im)((?:[a-z0-9_-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|credential|private[_-]?key)[a-z0-9_-]*)\s*[:=]\s*)([^\r\n]+)`)
	bearerPattern        = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*`)
	sensitiveSQLPattern  = regexp.MustCompile(`(?i)\b[a-z0-9_-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|credential|private[_-]?key)[a-z0-9_-]*\b`)
	sqlStringPattern     = regexp.MustCompile(`(?s)'(?:''|[^'])*'`)
)

func Text(value string) TextResult {
	redacted := value
	redacted = privateKeyPattern.ReplaceAllString(redacted, Marker)
	redacted = connectionURLPattern.ReplaceAllString(redacted, `${1}`+Marker+`@`)
	redacted = secretLinePattern.ReplaceAllString(redacted, `${1}`+Marker)
	redacted = bearerPattern.ReplaceAllString(redacted, `${1}`+Marker)
	if sensitiveSQLPattern.MatchString(redacted) {
		redacted = sqlStringPattern.ReplaceAllString(redacted, Marker)
	}
	return TextResult{Value: redacted, Redacted: redacted != value}
}

func Rows(columns []string, rows [][]string) ([][]string, bool) {
	maskedColumns := make(map[int]struct{})
	for index, column := range columns {
		if sensitiveColumn(column) {
			maskedColumns[index] = struct{}{}
		}
	}
	redacted := len(maskedColumns) != 0
	result := make([][]string, len(rows))
	for rowIndex, row := range rows {
		result[rowIndex] = append([]string(nil), row...)
		for columnIndex := range result[rowIndex] {
			if _, sensitive := maskedColumns[columnIndex]; sensitive {
				result[rowIndex][columnIndex] = Marker
				continue
			}
			text := Text(result[rowIndex][columnIndex])
			result[rowIndex][columnIndex] = text.Value
			redacted = redacted || text.Redacted
		}
	}
	return result, redacted
}

func sensitiveColumn(value string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(value))
	for _, sensitive := range []string{"password", "passwd", "secret", "token", "apikey", "accesskey", "authorization", "cookie", "credential", "privatekey", "rolpassword", "authenticationstring"} {
		if strings.Contains(normalized, sensitive) {
			return true
		}
	}
	switch normalized {
	case "pwd":
		return true
	default:
		return false
	}
}
