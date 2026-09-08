// Command client reads a local JSON file of raw scan records, sends them to
// the fingerprint server, and prints the results.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"banner-fingerprint/internal/client"
)

var version = "dev"

func main() {
	cfg := client.Config{}
	flag.StringVar(&cfg.ServerURL, "server", defaultServerURL(), "server base URL (e.g. http://localhost:8080)")
	flag.StringVar(&cfg.InputFile, "file", defaultInputFile(), "input JSON file path")
	flag.BoolVar(&cfg.JSON, "json", false, "print raw JSON instead of a table")
	flag.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "HTTP request timeout")
	flag.Parse()

	if err := client.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "client error:", err)
		os.Exit(1)
	}
}

func defaultServerURL() string {
	if u := os.Getenv("SERVER_URL"); u != "" {
		return u
	}
	return "http://localhost:8080"
}

func defaultInputFile() string {
	if f := os.Getenv("INPUT_FILE"); f != "" {
		return f
	}
	return "data/input.json"
}
