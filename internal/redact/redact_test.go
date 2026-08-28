package redact

import (
	"strings"
	"testing"
)

func TestRedactMasksSecretsWithoutChangingOrdinaryDiagnostics(t *testing.T) {
	t.Parallel()

	input := "db_password=correct-horse\nAuthorization: Bearer token-value\npostgres://ops:secret@db.example/app\n-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-data\n-----END OPENSSH PRIVATE KEY-----"
	result := Text(input)
	if !result.Redacted {
		t.Fatal("Text() did not report a redaction")
	}
	for _, secret := range []string{"correct-horse", "token-value", ":secret@", "private-data"} {
		if strings.Contains(result.Value, secret) {
			t.Errorf("redacted value still contains %q: %q", secret, result.Value)
		}
	}
	ordinary := Text("Mem: 7901 1404 2897")
	if ordinary.Redacted || ordinary.Value != "Mem: 7901 1404 2897" {
		t.Fatalf("ordinary diagnostic = %#v", ordinary)
	}
}

func TestRedactRowsMasksSensitiveColumns(t *testing.T) {
	t.Parallel()

	rows, redacted := Rows([]string{"id", "api_token", "state"}, [][]string{{"1", "token-value", "ready"}})
	if !redacted || rows[0][1] != Marker || rows[0][0] != "1" || rows[0][2] != "ready" {
		t.Fatalf("Rows() = %#v, redacted = %v", rows, redacted)
	}
}

func TestRedactRowsMasksSensitiveColumnVariants(t *testing.T) {
	t.Parallel()

	rows, redacted := Rows([]string{"id", "api_token_hash", "refresh_token", "client_secret", "access_key_id"}, [][]string{{"1", "hash", "refresh", "secret", "AKIA"}})
	if !redacted {
		t.Fatal("Rows() did not report sensitive column redaction")
	}
	for index := 1; index < len(rows[0]); index++ {
		if rows[0][index] != Marker {
			t.Fatalf("Rows() sensitive value at %d = %q", index, rows[0][index])
		}
	}
}

func TestRedactMasksSQLLiteralWhenStatementUsesSensitiveField(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"statement=INSERT INTO users (username, password) VALUES ('ops', 'do-not-persist')",
		"statement=INSERT INTO jobs (api_token) VALUES ('do-not-persist')",
	} {
		result := Text(input)
		if !result.Redacted || strings.Contains(result.Value, "do-not-persist") {
			t.Fatalf("Text(%q) = %#v", input, result)
		}
	}
}
