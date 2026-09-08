package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// OsHintKeyword maps a case-insensitive substring found in a banner to a
// human-friendly operating system label. Keywords are evaluated in slice
// order, so more specific terms should come first.
type OsHintKeyword struct {
	Keyword string `json:"keyword"`
	Label   string `json:"label"`
}

// Rule describes how to recognize one protocol/product from a raw banner.
// Rules are pure data (see rules/rules.json) and are intentionally decoupled
// from the engine code. Field meanings:
//
//   - match:        regular expression (RE2) tested against the raw banner.
//   - product:      static product name; when empty, product_group is used.
//   - product_group: capture-group index (1-based) to read the product from.
//   - version_group: capture-group index (1-based) to read the version from.
//   - confidence_by_product: optional per-product confidence override.
type Rule struct {
	ID                  string             `json:"id"`
	Priority            int                `json:"priority"`
	Match               string             `json:"match"`
	Protocol            string             `json:"protocol"`
	Product             string             `json:"product,omitempty"`
	ProductGroup        int                `json:"product_group,omitempty"`
	VersionGroup        int                `json:"version_group,omitempty"`
	Confidence          float64            `json:"confidence"`
	ConfidenceByProduct map[string]float64 `json:"confidence_by_product,omitempty"`
	OsHintKeywords      []OsHintKeyword    `json:"os_hint_keywords,omitempty"`
}

// LoadRulesFile reads and parses a rules file from disk.
func LoadRulesFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file %q: %w", path, err)
	}
	return ParseRules(data)
}

// ParseRules parses rule definitions and orders them by descending priority
// (stable within a priority, preserving the file order).
func ParseRules(data []byte) ([]Rule, error) {
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	for i, r := range rules {
		if r.Match == "" {
			return nil, fmt.Errorf("rule %d (%q): empty match regex", i, r.ID)
		}
		if r.Protocol == "" {
			return nil, fmt.Errorf("rule %d (%q): empty protocol", i, r.ID)
		}
		if r.Confidence < 0 || r.Confidence > 1 {
			return nil, fmt.Errorf("rule %d (%q): confidence %v out of [0,1]", i, r.ID, r.Confidence)
		}
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority > rules[j].Priority })
	return rules, nil
}

// ResolveRulesPath returns the first existing file path from candidates, or an
// error if none exist. Used to pick between an explicit RULES_PATH env value
// and conventional on-disk locations.
func ResolveRulesPath(candidates []string) (string, error) {
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("no rules file found in %v", candidates)
}
