package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

// dep is one resolved dependency, as pinned by a lockfile.
//
// Only resolved versions are considered. A range in a manifest says what the
// project would accept; the lockfile says what it actually installs, and it is
// the installed version whose provenance is in question.
type dep struct {
	Ecosystem string // "npm" | "go"
	Name      string
	Version   string
	File      string // repo-relative lockfile the pin came from
	Line      int    // best-effort line, for a clickable finding
	Direct    bool
}

func (d dep) key() string { return d.Ecosystem + "/" + d.Name + "@" + d.Version }

// collectDeps walks the workspace for lockfiles and returns every pinned
// dependency it can resolve.
//
// Directories that hold installed third-party trees are skipped: their
// contents are not this project's pins, and node_modules in particular would
// multiply the registry calls by an order of magnitude for no added coverage.
func collectDeps(root string) ([]dep, []string, error) {
	var deps []dep
	var files []string

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip, do not abort the scan
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "node_modules", "vendor", ".git", "testdata", "dist":
				return filepath.SkipDir
			}
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}

		switch entry.Name() {
		case "package-lock.json":
			d, pErr := parseNPMLock(path, rel)
			if pErr != nil {
				return nil
			}
			deps = append(deps, d...)
			files = append(files, rel)
		case "go.mod":
			d, pErr := parseGoMod(path, rel)
			if pErr != nil {
				return nil
			}
			deps = append(deps, d...)
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return dedupe(deps), files, nil
}

// dedupe collapses the same package@version appearing in several lockfiles.
// One registry answer covers all of them, and one finding is enough.
func dedupe(in []dep) []dep {
	seen := make(map[string]bool, len(in))
	out := make([]dep, 0, len(in))
	for _, d := range in {
		if seen[d.key()] {
			continue
		}
		seen[d.key()] = true
		out = append(out, d)
	}
	return out
}

type npmLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version  string `json:"version"`
		Resolved string `json:"resolved"`
		Link     bool   `json:"link"`
		Dev      bool   `json:"dev"`
	} `json:"packages"`
}

func parseNPMLock(path, rel string) ([]dep, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	if lock.LockfileVersion < 2 {
		// v1 keys dependencies differently. Rather than half-parse it, say so:
		// a lockfile silently contributing nothing is the failure mode this
		// plugin exists to avoid.
		return nil, fmt.Errorf("%s: lockfileVersion %d is not supported (need >= 2)", rel, lock.LockfileVersion)
	}

	out := make([]dep, 0, len(lock.Packages))
	for key, pkg := range lock.Packages {
		if key == "" || pkg.Link || pkg.Version == "" {
			continue // root project, or a workspace symlink: not a registry pin
		}
		idx := strings.LastIndex(key, "node_modules/")
		if idx < 0 {
			continue // a workspace package, not something fetched from npm
		}
		name := key[idx+len("node_modules/"):]
		if name == "" {
			continue
		}
		out = append(out, dep{
			Ecosystem: "npm",
			Name:      name,
			Version:   pkg.Version,
			File:      rel,
			Line:      1,
			Direct:    strings.Count(key, "node_modules/") == 1,
		})
	}
	return out, nil
}

func parseGoMod(path, rel string) ([]dep, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := modfile.Parse(rel, raw, nil)
	if err != nil {
		return nil, err
	}

	out := make([]dep, 0, len(f.Require))
	for _, r := range f.Require {
		if r == nil || r.Mod.Path == "" || r.Mod.Version == "" {
			continue
		}
		line := 1
		if r.Syntax != nil {
			line = r.Syntax.Start.Line
		}
		out = append(out, dep{
			Ecosystem: "go",
			Name:      r.Mod.Path,
			Version:   r.Mod.Version,
			File:      rel,
			Line:      line,
			Direct:    !r.Indirect,
		})
	}
	return out, nil
}
