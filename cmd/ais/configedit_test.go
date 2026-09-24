package main

import (
	"strings"
	"testing"

	pb "ais/generated/artisan/watchdog"
)

func TestResolveAppID(t *testing.T) {
	expected := []string{"ais_12345678", "ais_1234abcd", "ais_deadbeef"}
	tests := []struct {
		input string
		want  string
	}{
		{"ais_deadbeef", "ais_deadbeef"},
		{"deadbeef", "ais_deadbeef"},
		{"dead", "ais_deadbeef"},
	}
	for _, test := range tests {
		got, err := resolveAppID(test.input, expected)
		if err != nil {
			t.Fatalf("resolveAppID(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("resolveAppID(%q) = %q, want %q", test.input, got, test.want)
		}
	}

	if _, err := resolveAppID("1234", expected); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous prefix error, got %v", err)
	}
	if _, err := resolveAppID("missing", expected); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

func TestParseConfigKind(t *testing.T) {
	if kind, err := parseConfigKind("config"); err != nil || kind != pb.ConfigFileKind_CONFIG_FILE_KIND_CONFIG {
		t.Fatalf("parse config = %v, %v", kind, err)
	}
	if kind, err := parseConfigKind("overrides"); err != nil || kind != pb.ConfigFileKind_CONFIG_FILE_KIND_OVERRIDES {
		t.Fatalf("parse overrides = %v, %v", kind, err)
	}
	if _, err := parseConfigKind("settings"); err == nil {
		t.Fatal("expected unknown-kind error")
	}
}

func TestValidateLocalTOML(t *testing.T) {
	if err := validateLocalTOML("[app]\nname = \"ok\"\n"); err != nil {
		t.Fatalf("valid TOML rejected: %v", err)
	}
	for _, invalid := range []string{"", "not [ toml"} {
		if err := validateLocalTOML(invalid); err == nil {
			t.Fatalf("invalid TOML accepted: %q", invalid)
		}
	}
}
