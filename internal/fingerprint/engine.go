package fingerprint

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Engine applies a set of compiled rules to raw banners.
type Engine struct {
	rules []compiledRule
}

type compiledRule struct {
	Rule
	re *regexp.Regexp
}

// NewEngine compiles the supplied rules. Rules are applied in descending
// priority order (stable within a priority).
func NewEngine(rules []Rule) (*Engine, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		re, err := regexp.Compile(r.Match)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", r.ID, err)
		}
		compiled = append(compiled, compiledRule{Rule: r, re: re})
	}
	return &Engine{rules: compiled}, nil
}

// Identify returns the recognition result for a single record. Unmatched input
// yields Protocol "unknown" with empty fields and zero confidence — never an
// error, so a single unrecognized banner cannot fail a batch.
func (e *Engine) Identify(rec Record) Result {
	res := Result{IP: rec.IP, Port: rec.Port, Protocol: "unknown"}
	for _, cr := range e.rules {
		m := cr.re.FindStringSubmatch(rec.Banner)
		if m == nil {
			continue
		}
		res.Protocol = cr.Protocol
		res.Product = cr.Product
		if res.Product == "" && cr.ProductGroup > 0 && cr.ProductGroup < len(m) {
			res.Product = m[cr.ProductGroup]
		}
		if cr.VersionGroup > 0 && cr.VersionGroup < len(m) {
			res.Version = m[cr.VersionGroup]
		}
		res.OsHint = matchOsHint(rec.Banner, cr.OsHintKeywords)
		res.Confidence = round2(cr.Confidence)
		if c, ok := cr.ConfidenceByProduct[res.Product]; ok {
			res.Confidence = round2(c)
		}
		break
	}
	return res
}

// IdentifyBatch identifies many records, preserving input order.
func (e *Engine) IdentifyBatch(recs []Record) []Result {
	out := make([]Result, 0, len(recs))
	for _, r := range recs {
		out = append(out, e.Identify(r))
	}
	return out
}

func matchOsHint(banner string, kws []OsHintKeyword) string {
	low := strings.ToLower(banner)
	for _, k := range kws {
		if k.Keyword == "" {
			continue
		}
		if strings.Contains(low, strings.ToLower(k.Keyword)) {
			return k.Label
		}
	}
	return ""
}

func round2(f float64) float64 {
	return math.Round(f*100) / 100
}
