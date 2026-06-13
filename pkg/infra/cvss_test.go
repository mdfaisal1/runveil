package infra

import (
	"math"
	"testing"
)

func TestCVSSBaseScore_CanonicalVectors(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   float64
	}{
		{"full-impact RCE", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"availability-only DoS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"changed-scope XSS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"low", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1},
		{"none", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"cvss 3.0 prefix", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}
	for _, c := range cases {
		got, ok := CVSSBaseScore([]OSVSeverity{{Type: "CVSS_V3", Score: c.vector}})
		if !ok {
			t.Errorf("%s: expected ok", c.name)
			continue
		}
		if math.Abs(got-c.want) > 0.05 {
			t.Errorf("%s: score = %.2f, want %.1f", c.name, got, c.want)
		}
	}
}

func TestCVSSBaseScore_NoV3Vector(t *testing.T) {
	if _, ok := CVSSBaseScore(nil); ok {
		t.Error("nil severities should not produce a score")
	}
	// Only a v4 vector present → not handled, returns false.
	if _, ok := CVSSBaseScore([]OSVSeverity{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L"}}); ok {
		t.Error("v4-only should return false")
	}
	// Garbage vector → false, not a panic.
	if _, ok := CVSSBaseScore([]OSVSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/garbage"}}); ok {
		t.Error("garbage vector should return false")
	}
}
