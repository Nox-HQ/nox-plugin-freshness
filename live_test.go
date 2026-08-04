package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// Live tests hit the real registries. They are gated so CI stays hermetic —
// a scanner whose test suite depends on npm being up is a scanner that goes
// red for reasons unrelated to the code.
//
//	FRESHNESS_LIVE=1 go test -run TestLive -v ./...
func skipUnlessLive(t *testing.T) {
	t.Helper()
	if os.Getenv("FRESHNESS_LIVE") == "" {
		t.Skip("set FRESHNESS_LIVE=1 to run tests that query real registries")
	}
}

// TestLiveKeyvCompromise checks the plugin against the case it was written
// for: keyv@6.0.0, published 2026-08-04T09:35Z by the npm worm, for which
// OSV had no advisory at the time of writing.
func TestLiveKeyvCompromise(t *testing.T) {
	skipUnlessLive(t)

	c := newClient()
	got := c.lookupNPM(context.Background(), dep{Ecosystem: "npm", Name: "keyv", Version: "6.0.0"})
	if !got.Checked {
		t.Fatalf("Checked = false, err = %v", got.Err)
	}

	t.Logf("keyv@6.0.0 published=%v withdrawn=%v reason=%q publisher=%q prev=%s/%q",
		got.PublishedAt, got.Withdrawn, got.WithdrawnReason, got.Publisher, got.PrevVersion, got.PrevPublisher)

	if got.PublishedAt.IsZero() {
		t.Error("PublishedAt is zero; the registry does carry a time for this version")
	}
	if !got.Withdrawn {
		t.Error("Withdrawn = false; npm rolled `latest` back to 5.6.0, which FRESH-002 should catch")
	}

	// The control: a mature version of the same package must stay quiet, or
	// the rule is just flagging everything.
	calm := c.lookupNPM(context.Background(), dep{Ecosystem: "npm", Name: "keyv", Version: "5.6.0"})
	if !calm.Checked {
		t.Fatalf("control: Checked = false, err = %v", calm.Err)
	}
	if calm.Withdrawn {
		t.Errorf("control: keyv@5.6.0 reported withdrawn (%q); it is the current latest", calm.WithdrawnReason)
	}
	if time.Since(calm.PublishedAt) < 7*24*time.Hour {
		t.Errorf("control: keyv@5.6.0 looks fresh (published %v); expected a mature release", calm.PublishedAt)
	}
}

// TestLiveGoProxy confirms the Go path against real modules: publish times
// resolve, and an ordinary dependency is not reported as withdrawn.
func TestLiveGoProxy(t *testing.T) {
	skipUnlessLive(t)

	c := newClient()
	for _, d := range []dep{
		{Ecosystem: "go", Name: "google.golang.org/grpc", Version: "v1.83.0"},
		{Ecosystem: "go", Name: "golang.org/x/crypto", Version: "v0.54.0"},
	} {
		got := c.lookupGo(context.Background(), d)
		if !got.Checked {
			t.Errorf("%s: Checked = false, err = %v", d.key(), got.Err)
			continue
		}
		t.Logf("%s published=%v withdrawn=%v", d.key(), got.PublishedAt, got.Withdrawn)
		if got.PublishedAt.IsZero() {
			t.Errorf("%s: PublishedAt is zero", d.key())
		}
		if got.Withdrawn {
			t.Errorf("%s: reported withdrawn (%q); neither module is retracted", d.key(), got.WithdrawnReason)
		}
	}
}

// TestLiveCaseFoldedModulePath guards the proxy's escaping rule: an uppercase
// letter in a module path becomes "!" + lowercase, and getting this wrong
// turns every such dependency into an unchecked one.
func TestLiveCaseFoldedModulePath(t *testing.T) {
	skipUnlessLive(t)

	c := newClient()
	got := c.lookupGo(context.Background(), dep{
		Ecosystem: "go", Name: "github.com/BurntSushi/toml", Version: "v1.4.0",
	})
	if !got.Checked {
		t.Fatalf("Checked = false, err = %v (module path escaping is likely wrong)", got.Err)
	}
	t.Logf("github.com/BurntSushi/toml@v1.4.0 published=%v", got.PublishedAt)
}
