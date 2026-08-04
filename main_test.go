package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
)

func TestConformance(t *testing.T) {
	manifest := sdk.NewManifest("freshness", "0.0.0-test").
		Capability("freshness", "Dependency provenance: version age, registry withdrawal, publisher changes").
		Tool("scan", "Flag dependencies whose provenance is suspicious", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive),
			sdk.WithNetworkHosts("registry.npmjs.org", "proxy.golang.org")).
		Build()

	srv := sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)

	sdk.RunForTrack(t, srv, registry.Track("supply-chain"))
}

// npmServer serves a packument shaped like registry.npmjs.org's.
func npmServer(t *testing.T, packuments map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.EscapedPath(), "/")
		// Scoped names arrive percent-encoded; the map is keyed by the real name.
		name = strings.ReplaceAll(name, "%2f", "/")
		name = strings.ReplaceAll(name, "%2F", "/")
		p, ok := packuments[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(p)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLookupNPM(t *testing.T) {
	now := time.Now().UTC()

	// Modelled on keyv as it stood on 2026-08-04: 6.0.0 published that
	// morning, `latest` rolled back to 5.6.0, a different publishing account.
	keyv := map[string]any{
		"dist-tags": map[string]string{"latest": "5.6.0"},
		"time": map[string]string{
			"5.5.3": now.Add(-90 * 24 * time.Hour).Format(time.RFC3339),
			"5.6.0": now.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
			"6.0.0": now.Add(-3 * time.Hour).Format(time.RFC3339),
		},
		"versions": map[string]any{
			"5.5.3": map[string]any{"_npmUser": map[string]string{"name": "jaredwray"}},
			"5.6.0": map[string]any{"_npmUser": map[string]string{"name": "jaredwray"}},
			"6.0.0": map[string]any{"_npmUser": map[string]string{"name": "attacker"}},
		},
	}
	// A package whose compromised version has since been unpublished.
	pulled := map[string]any{
		"dist-tags": map[string]string{"latest": "1.2.0"},
		"time": map[string]string{
			"1.2.0": now.Add(-60 * 24 * time.Hour).Format(time.RFC3339),
		},
		"versions": map[string]any{
			"1.2.0": map[string]any{"_npmUser": map[string]string{"name": "maintainer"}},
		},
	}
	// The ordinary case: a mature version with nothing to say about it.
	calm := map[string]any{
		"dist-tags": map[string]string{"latest": "8.5.25"},
		"time": map[string]string{
			"8.5.24": now.Add(-200 * 24 * time.Hour).Format(time.RFC3339),
			"8.5.25": now.Add(-120 * 24 * time.Hour).Format(time.RFC3339),
		},
		"versions": map[string]any{
			"8.5.24": map[string]any{"_npmUser": map[string]string{"name": "ai"}},
			"8.5.25": map[string]any{"_npmUser": map[string]string{"name": "ai"}},
		},
	}

	srv := npmServer(t, map[string]any{
		"keyv": keyv, "pulled": pulled, "postcss": calm, "@scope/thing": calm,
	})

	tests := []struct {
		name           string
		dep            dep
		wantWithdrawn  bool
		wantReasonHas  string
		wantReasonAlso string
		wantFresh      bool
		wantPublisher  string
		wantPrev       string
	}{
		{
			name:          "compromised version: fresh, rolled back, new publisher",
			dep:           dep{Ecosystem: "npm", Name: "keyv", Version: "6.0.0"},
			wantWithdrawn: true,
			wantReasonHas: "rolled back",
			wantFresh:     true,
			wantPublisher: "attacker",
			wantPrev:      "jaredwray",
		},
		{
			// Both withdrawal signals are true here, and both must survive:
			// 1.3.0 is absent from the registry *and* sits above `latest`.
			name:           "version unpublished after the fact",
			dep:            dep{Ecosystem: "npm", Name: "pulled", Version: "1.3.0"},
			wantWithdrawn:  true,
			wantReasonHas:  "no longer published",
			wantReasonAlso: "rolled back",
			wantPrev:       "maintainer", // 1.2.0 is the highest release below 1.3.0
		},
		{
			name:          "mature version is not flagged",
			dep:           dep{Ecosystem: "npm", Name: "postcss", Version: "8.5.25"},
			wantPublisher: "ai",
			wantPrev:      "ai",
		},
		{
			name:          "scoped names resolve",
			dep:           dep{Ecosystem: "npm", Name: "@scope/thing", Version: "8.5.25"},
			wantPublisher: "ai",
			wantPrev:      "ai",
		},
	}

	c := newClient()
	c.npmBase = srv.URL

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := c.lookupNPM(context.Background(), tc.dep)
			if !got.Checked {
				t.Fatalf("Checked = false, err = %v", got.Err)
			}
			if got.Withdrawn != tc.wantWithdrawn {
				t.Errorf("Withdrawn = %v, want %v (reason %q)", got.Withdrawn, tc.wantWithdrawn, got.WithdrawnReason)
			}
			if tc.wantReasonHas != "" && !strings.Contains(got.WithdrawnReason, tc.wantReasonHas) {
				t.Errorf("WithdrawnReason = %q, want it to contain %q", got.WithdrawnReason, tc.wantReasonHas)
			}
			if tc.wantReasonAlso != "" && !strings.Contains(got.WithdrawnReason, tc.wantReasonAlso) {
				t.Errorf("WithdrawnReason = %q, want it to also contain %q (both signals must survive)", got.WithdrawnReason, tc.wantReasonAlso)
			}
			isFresh := !got.PublishedAt.IsZero() && time.Since(got.PublishedAt) < 7*24*time.Hour
			if isFresh != tc.wantFresh {
				t.Errorf("fresh = %v, want %v (published %v)", isFresh, tc.wantFresh, got.PublishedAt)
			}
			if got.Publisher != tc.wantPublisher {
				t.Errorf("Publisher = %q, want %q", got.Publisher, tc.wantPublisher)
			}
			if got.PrevPublisher != tc.wantPrev {
				t.Errorf("PrevPublisher = %q, want %q", got.PrevPublisher, tc.wantPrev)
			}
		})
	}
}

func TestLookupNPMUnreachableIsNotClean(t *testing.T) {
	// The property the whole plugin turns on: a registry that cannot be
	// reached must not produce a checked-and-clean result.
	c := newClient()
	c.npmBase = "http://127.0.0.1:1" // nothing listening

	got := c.lookupNPM(context.Background(), dep{Ecosystem: "npm", Name: "keyv", Version: "6.0.0"})
	if got.Checked {
		t.Fatal("Checked = true for an unreachable registry; absence of an answer must not read as a clean package")
	}
	if got.Err == nil {
		t.Error("Err = nil, want the transport failure to be reported")
	}
}

func TestLookupGoRetractAndAge(t *testing.T) {
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@v/v1.2.3.info"):
			_ = json.NewEncoder(w).Encode(goVersionInfo{Version: "v1.2.3", Time: now.Add(-2 * time.Hour)})
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_ = json.NewEncoder(w).Encode(goVersionInfo{Version: "v1.2.4", Time: now})
		case strings.HasSuffix(r.URL.Path, "/@v/v1.2.4.mod"):
			_, _ = w.Write([]byte("module example.com/m\n\ngo 1.25\n\nretract v1.2.3 // published from a compromised account\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c := newClient()
	c.goBase = srv.URL

	got := c.lookupGo(context.Background(), dep{Ecosystem: "go", Name: "example.com/m", Version: "v1.2.3"})
	if !got.Checked {
		t.Fatalf("Checked = false, err = %v", got.Err)
	}
	if !got.Withdrawn {
		t.Error("Withdrawn = false, want the retract directive to be honoured")
	}
	if !strings.Contains(got.WithdrawnReason, "compromised account") {
		t.Errorf("WithdrawnReason = %q, want the author's rationale carried through", got.WithdrawnReason)
	}
	if age := time.Since(got.PublishedAt); age > 24*time.Hour {
		t.Errorf("PublishedAt = %v (age %v), want the proxy's Time field", got.PublishedAt, age)
	}
}

func TestFingerprintIsPathIndependent(t *testing.T) {
	// Regression guard. nox baselines are keyed by fingerprint, and one that
	// varies with the scan directory cannot be accepted durably: it differs
	// between a developer checkout, a worktree and CI, so a reviewed finding
	// reappears as net-new on every machine.
	a := dep{Ecosystem: "npm", Name: "keyv", Version: "6.0.0", File: "app/package-lock.json", Line: 1}
	b := dep{Ecosystem: "npm", Name: "keyv", Version: "6.0.0", File: "/elsewhere/deep/package-lock.json", Line: 999}

	if fingerprint("FRESH-001", a) != fingerprint("FRESH-001", b) {
		t.Error("fingerprint changed with file path/line; it must depend only on rule and package coordinates")
	}
	if fingerprint("FRESH-001", a) == fingerprint("FRESH-002", a) {
		t.Error("different rules produced the same fingerprint")
	}
	if fingerprint("FRESH-001", a) == fingerprint("FRESH-001", dep{Ecosystem: "npm", Name: "keyv", Version: "5.6.0"}) {
		t.Error("different versions produced the same fingerprint")
	}
}

func TestParseNPMLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	content := `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"version": "1.0.0"},
	    "node_modules/keyv": {"version": "6.0.0"},
	    "node_modules/@scope/thing": {"version": "1.0.0"},
	    "node_modules/a/node_modules/nested": {"version": "2.0.0"},
	    "node_modules/linked": {"version": "1.0.0", "link": true},
	    "packages/workspace-pkg": {"version": "0.0.1"}
	  }
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := parseNPMLock(path, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]dep{}
	for _, d := range got {
		byName[d.Name] = d
	}

	for _, want := range []string{"keyv", "@scope/thing", "nested"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("missing %q; got %v", want, keysOf(byName))
		}
	}
	if _, ok := byName["linked"]; ok {
		t.Error("workspace symlink was treated as a registry pin")
	}
	if len(got) != 3 {
		t.Errorf("len = %d, want 3 (root and workspace entries excluded); got %v", len(got), keysOf(byName))
	}
	if !byName["keyv"].Direct {
		t.Error("top-level node_modules/keyv should be Direct")
	}
	if byName["nested"].Direct {
		t.Error("nested dependency should not be Direct")
	}
}

func TestParseNPMLockRejectsV1(t *testing.T) {
	// A v1 lockfile silently contributing zero dependencies would be exactly
	// the failure this plugin exists to make impossible.
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(path, []byte(`{"lockfileVersion": 1, "dependencies": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseNPMLock(path, "package-lock.json"); err == nil {
		t.Error("err = nil for lockfileVersion 1, want an explicit unsupported error")
	}
}

func TestParseGoMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	content := `module example.com/x

go 1.25

require (
	google.golang.org/grpc v1.83.0
	golang.org/x/crypto v0.54.0 // indirect
)
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := parseGoMod(path, "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	byName := map[string]dep{}
	for _, d := range got {
		byName[d.Name] = d
	}
	if !byName["google.golang.org/grpc"].Direct {
		t.Error("grpc should be Direct")
	}
	if byName["golang.org/x/crypto"].Direct {
		t.Error("x/crypto is marked // indirect and should not be Direct")
	}
	if byName["google.golang.org/grpc"].Line <= 1 {
		t.Error("Line should point at the require entry, not the file start")
	}
}

func TestDedupe(t *testing.T) {
	in := []dep{
		{Ecosystem: "npm", Name: "a", Version: "1", File: "one/package-lock.json"},
		{Ecosystem: "npm", Name: "a", Version: "1", File: "two/package-lock.json"},
		{Ecosystem: "npm", Name: "a", Version: "2", File: "one/package-lock.json"},
		{Ecosystem: "go", Name: "a", Version: "1", File: "go.mod"},
	}
	if got := dedupe(in); len(got) != 3 {
		t.Errorf("len = %d, want 3 (same pkg@version in two lockfiles collapses; version and ecosystem still distinguish)", len(got))
	}
}

func keysOf(m map[string]dep) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
