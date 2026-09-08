// Package fingerprint implements a rule-driven banner fingerprint engine.
//
// The engine itself contains no hard-coded protocol knowledge: every
// recognition rule lives in rules/rules.json and is loaded at startup, so
// adding or tuning a fingerprint never requires recompiling the binary.
package fingerprint

// Record is a single raw scan input item received from the client.
type Record struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result is the identification output for one Record. Unmatched input is
// reported as Protocol "unknown" with empty fields and zero confidence.
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OsHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}
