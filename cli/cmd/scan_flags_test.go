package cmd

import "testing"

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		in    string
		valid bool
	}{
		{"none", true},
		{"low", true},
		{"medium", true},
		{"high", true},
		{"critical", true},
		{"CRITICAL", true},
		{"weird", false},
	}
	for _, tt := range tests {
		_, err := parseFailOn(tt.in)
		if tt.valid && err != nil {
			t.Errorf("expected valid for %q, got err %v", tt.in, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("expected error for %q", tt.in)
		}
	}
}
