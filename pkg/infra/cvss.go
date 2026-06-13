package infra

import (
	"math"
	"strings"
)

// CVSSBaseScore computes the CVSS v3.0/3.1 base score from the first usable
// CVSS_V3 vector in the provided severities. It returns the score and true on
// success, or 0 and false when no v3 vector can be parsed.
//
// The v3.1 specification's scoring formula is implemented directly:
// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics
func CVSSBaseScore(sevs []OSVSeverity) (float64, bool) {
	for _, s := range sevs {
		v := strings.ToUpper(strings.TrimSpace(s.Score))
		if !strings.HasPrefix(v, "CVSS:3") {
			continue // only v3.x handled here (v4 scoring is out of scope)
		}
		if score, ok := cvss3BaseFromVector(v); ok {
			return score, true
		}
	}
	return 0, false
}

func cvss3BaseFromVector(vec string) (float64, bool) {
	m := map[string]string{}
	for _, part := range strings.Split(vec, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}

	scope := m["S"] // "U" (unchanged) or "C" (changed)
	changed := scope == "C"

	av, ok1 := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[m["AV"]]
	ac, ok2 := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui, ok3 := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	// Privileges Required weighting depends on Scope.
	var pr float64
	var ok4 bool
	if changed {
		pr, ok4 = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}[m["PR"]]
	} else {
		pr, ok4 = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	}
	impact := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	c, ok5 := impact[m["C"]]
	i, ok6 := impact[m["I"]]
	a, ok7 := impact[m["A"]]

	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) || (scope != "U" && scope != "C") {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impactScore float64
	if changed {
		impactScore = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impactScore = 6.42 * iss
	}
	if impactScore <= 0 {
		return 0.0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	raw := impactScore + exploitability
	if changed {
		raw = 1.08 * raw
	}
	return cvssRoundup(math.Min(raw, 10)), true
}

// cvssRoundup implements the CVSS v3.1 Roundup function (round up to 1 decimal).
func cvssRoundup(x float64) float64 {
	intInput := int(math.Round(x * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000
	}
	return (math.Floor(float64(intInput)/10000) + 1) / 10
}
