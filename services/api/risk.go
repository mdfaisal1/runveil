package main

import "strings"

// riskScore fuses the three signals Runveil cares about into a single 0–100 score
// so the most important findings sort to the top:
//
//   - severity     — CVSS band weight (CRITICAL highest)
//   - reachability — dormant (dev-only / unreachable) findings are heavily downweighted
//   - evidence     — runtime observations raise confidence the issue is actually hot
//
// A HIGH that is actively executing can outrank a CRITICAL never seen at runtime —
// which is exactly the runtime-native prioritization Runveil is built on.
func riskScore(reachable bool, severity string, evidenceCount int64) int {
	sevWeight := map[string]float64{
		"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1,
	}[strings.ToUpper(strings.TrimSpace(severity))]
	if sevWeight == 0 {
		sevWeight = 1 // unknown severity → treat as low, not zero
	}

	reachFactor := 0.15 // dormant: present but not on a production path
	if reachable {
		reachFactor = 1.0
	}

	// Evidence boosts up to 2x, saturating at 20 observations.
	cap := evidenceCount
	if cap > 20 {
		cap = 20
	}
	evidenceFactor := 1.0 + float64(cap)/20.0

	// Max raw = 10 * 1.0 * 2.0 = 20  → scale ×5 to land on 0–100.
	score := int(sevWeight*reachFactor*evidenceFactor*5 + 0.5)
	if score > 100 {
		score = 100
	}
	return score
}
