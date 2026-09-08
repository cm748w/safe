// Package jsonx provides JSON decoding helpers tolerant of raw-banner dumps.
//
// Network scanners often serialize raw bytes with non-standard "\xNN" escapes
// (e.g. "\x00", "\x16\x03\x01"). Standard JSON has no "\x" escape, so a strict
// decoder rejects such payloads. Decode below first tries strict parsing and
// only rewrites "\xNN" to "\u00NN" when strict parsing fails, keeping standard
// JSON untouched.
package jsonx

import (
	"bytes"
	"encoding/json"
	"regexp"
)

var hexEsc = regexp.MustCompile(`\\x([0-9A-Fa-f]{2})`)

// Decode unmarshals data into v. Strict JSON is parsed first; if that fails
// and the payload contains "\xNN" escapes, those are rewritten to "\u00NN" and
// the parse is retried. Note: "\xNN" denotes a raw byte, while "\u00NN" is a
// Unicode code point, so byte values >= 0x80 round-trip through UTF-8 rather
// than as a single byte. All fingerprints used here match ASCII/control
// prefixes, so this is sufficient in practice.
func Decode(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err == nil {
		return nil
	} else if !bytes.Contains(data, []byte(`\x`)) {
		return err
	}
	rewritten := hexEsc.ReplaceAll(data, []byte(`\u00$1`))
	return json.Unmarshal(rewritten, v)
}
