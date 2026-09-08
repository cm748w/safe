// Package client implements the standalone CLI that reads a local JSON file of
// raw scan records, sends them to the server, and prints the identification
// results.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"banner-fingerprint/internal/fingerprint"
	"banner-fingerprint/internal/jsonx"
)

// Config configures a client run.
type Config struct {
	ServerURL string
	InputFile string
	JSON      bool
	Timeout   time.Duration
}

// Run executes one identification round trip.
func Run(cfg Config) error {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	data, err := os.ReadFile(cfg.InputFile)
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}

	var records []fingerprint.Record
	if err := jsonx.Decode(data, &records); err != nil {
		return fmt.Errorf("parse input file %q: %w", cfg.InputFile, err)
	}
	if len(records) == 0 {
		return fmt.Errorf("input file %q contains no records", cfg.InputFile)
	}

	payload, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpClient := &http.Client{Timeout: cfg.Timeout}
	resp, err := httpClient.Post(cfg.ServerURL+"/fingerprint", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("post to %s: %w", cfg.ServerURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var results []fingerprint.Result
	if err := json.Unmarshal(body, &results); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if cfg.JSON {
		out, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal results: %w", err)
		}
		fmt.Println(string(out))
		return nil
	}

	printTable(results)
	return nil
}

func printTable(results []fingerprint.Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OsHint, r.Confidence)
	}
	w.Flush()
	fmt.Printf("\nidentified %d record(s)\n", len(results))
}
