package cmd

import (
	"encoding/json"
	"testing"
)

// A minimal npm lockfile (v3) exercising the dev/prod and direct/transitive cases.
const sampleLockfile = `{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo",
      "dependencies": { "axios": "^1.6.0" },
      "devDependencies": { "webpack": "^5.0.0" }
    },
    "node_modules/axios": { "version": "1.6.0" },
    "node_modules/follow-redirects": { "version": "1.15.0" },
    "node_modules/webpack": { "version": "5.90.0", "dev": true },
    "node_modules/loose-envify": { "version": "1.4.0", "devOptional": true },
    "node_modules/@scope/util": { "version": "2.1.0" }
  }
}`

func parseSample(t *testing.T) map[string]dep {
	t.Helper()
	var lock map[string]any
	if err := json.Unmarshal([]byte(sampleLockfile), &lock); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	deps := extractNpmPackages(lock)
	byName := map[string]dep{}
	for _, d := range deps {
		byName[d.name] = d
	}
	return byName
}

func TestExtractNpmPackages_DevAndDirect(t *testing.T) {
	deps := parseSample(t)

	cases := []struct {
		name       string
		wantVer    string
		wantDev    bool
		wantDirect bool
	}{
		{"axios", "1.6.0", false, true},              // production, direct
		{"follow-redirects", "1.15.0", false, false}, // production, transitive
		{"webpack", "5.90.0", true, true},            // dev-only, direct
		{"loose-envify", "1.4.0", true, false},       // devOptional → dev-only
		{"@scope/util", "2.1.0", false, false},       // scoped, production
	}

	for _, c := range cases {
		d, ok := deps[c.name]
		if !ok {
			t.Errorf("%s: not found in parsed deps", c.name)
			continue
		}
		if d.version != c.wantVer {
			t.Errorf("%s: version = %q, want %q", c.name, d.version, c.wantVer)
		}
		if d.dev != c.wantDev {
			t.Errorf("%s: dev = %v, want %v", c.name, d.dev, c.wantDev)
		}
		if d.direct != c.wantDirect {
			t.Errorf("%s: direct = %v, want %v", c.name, d.direct, c.wantDirect)
		}
	}

	// Root entry ("") must never appear as a package.
	if _, ok := deps[""]; ok {
		t.Error("root package entry leaked into deps")
	}
}

// reachability v1: a finding is reachable iff its package is not dev-only.
func TestReachabilityHeuristic(t *testing.T) {
	deps := parseSample(t)
	reachable := func(name string) bool { return !deps[name].dev }

	if !reachable("axios") {
		t.Error("axios (production) should be reachable")
	}
	if reachable("webpack") {
		t.Error("webpack (dev-only) should be dormant")
	}
	if reachable("loose-envify") {
		t.Error("loose-envify (devOptional) should be dormant")
	}
}

// npm lists the same package@version at multiple node_modules paths; the parser
// must return it once, and production presence must win over a dev-only copy.
func TestExtractNpmPackages_DedupesAndProductionWins(t *testing.T) {
	const lf = `{
      "packages": {
        "": { "dependencies": { "axios": "^1.6.0" } },
        "node_modules/axios": { "version": "1.6.0", "dev": true },
        "node_modules/nested/node_modules/axios": { "version": "1.6.0" },
        "node_modules/dupe": { "version": "2.0.0", "dev": true },
        "node_modules/a/node_modules/dupe": { "version": "2.0.0", "dev": true }
      }
    }`
	var lock map[string]any
	if err := json.Unmarshal([]byte(lf), &lock); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	deps := extractNpmPackages(lock)

	counts := map[string]int{}
	var axios, dupe dep
	for _, d := range deps {
		counts[d.name+"@"+d.version]++
		if d.name == "axios" {
			axios = d
		}
		if d.name == "dupe" {
			dupe = d
		}
	}
	if counts["axios@1.6.0"] != 1 {
		t.Errorf("axios should appear once, got %d", counts["axios@1.6.0"])
	}
	if axios.dev {
		t.Error("axios is production in one tree → must be reachable (dev=false)")
	}
	if !axios.direct {
		t.Error("axios is a direct dependency")
	}
	if !dupe.dev {
		t.Error("dupe is dev-only in every copy → must stay dev=true")
	}
}

func TestSortFindings_ReachableFirstThenSeverity(t *testing.T) {
	fs := []finding{
		{Package: "z-dormant", Severity: severityCritical, Reachable: false},
		{Package: "a-reach-low", Severity: severityLow, Reachable: true},
		{Package: "b-reach-high", Severity: severityHigh, Reachable: true},
	}
	sortFindings(fs)

	if !fs[0].Reachable || fs[0].Package != "b-reach-high" {
		t.Errorf("expected reachable HIGH first, got %+v", fs[0])
	}
	if !fs[1].Reachable || fs[1].Package != "a-reach-low" {
		t.Errorf("expected reachable LOW second, got %+v", fs[1])
	}
	if fs[2].Reachable {
		t.Errorf("expected dormant finding last, got %+v", fs[2])
	}
}
