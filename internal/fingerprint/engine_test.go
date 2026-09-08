package fingerprint

import (
	"math"
	"testing"
)

func loadTestEngine(t *testing.T) *Engine {
	t.Helper()
	path, err := ResolveRulesPath([]string{"../../rules/rules.json", "rules/rules.json"})
	if err != nil {
		t.Fatalf("resolve rules path: %v", err)
	}
	rules, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	e, err := NewEngine(rules)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return e
}

func approx(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

func TestIdentifyBatch(t *testing.T) {
	e := loadTestEngine(t)

	type want struct {
		protocol   string
		product    string
		version    string
		osHint     string
		confidence float64
	}

	cases := []struct {
		name string
		in   Record
		want want
	}{
		{"ssh-openssh-ubuntu", Record{"1.2.3.4", 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, want{"SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95}},
		{"http-nginx", Record{"1.2.3.5", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}, want{"HTTP", "nginx", "1.24.0", "", 0.9}},
		{"http-apache", Record{"1.2.3.6", 443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"}, want{"HTTP", "Apache", "2.4.57", "", 0.9}},
		{"mysql-8", Record{"1.2.3.7", 3306, "J\x00\x00\x00\n8.0.32\x00"}, want{"MySQL", "MySQL", "8.0.32", "", 0.9}},
		{"redis-err", Record{"1.2.3.8", 6379, "-ERR wrong number of arguments for 'get' command"}, want{"Redis", "Redis", "", "", 0.7}},
		{"ftp-proftpd", Record{"1.2.3.9", 21, "220 ProFTPD 1.3.7 Server (ProFTPD)"}, want{"FTP", "ProFTPD", "1.3.7", "", 0.9}},
		{"http-jetty", Record{"1.2.3.10", 8080, "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"}, want{"HTTP", "Jetty", "9.4.51", "", 0.85}},
		{"ssh-openssh-debian", Record{"1.2.3.11", 22, "SSH-2.0-OpenSSH_9.3 Debian-1"}, want{"SSH", "OpenSSH", "9.3", "Debian", 0.95}},
		{"http-nginx-ubuntu", Record{"1.2.3.12", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"}, want{"HTTP", "nginx", "1.18.0", "Ubuntu", 0.9}},
		{"http-apache-ubuntu", Record{"1.2.3.13", 443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"}, want{"HTTP", "Apache", "2.4.41", "Ubuntu", 0.9}},
		{"mysql-5", Record{"1.2.3.14", 3306, "J\x00\x00\x00\n5.7.42\x00"}, want{"MySQL", "MySQL", "5.7.42", "", 0.9}},
		{"redis-pong", Record{"1.2.3.15", 6379, "+PONG"}, want{"Redis", "Redis", "", "", 0.7}},
		{"ftp-vsftpd", Record{"1.2.3.16", 21, "220 (vsFTPd 3.0.5)"}, want{"FTP", "vsFTPd", "3.0.5", "", 0.9}},
		{"http-nginx-alt", Record{"1.2.3.17", 8443, "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3"}, want{"HTTP", "nginx", "1.25.3", "", 0.9}},
		{"ssh-1.99", Record{"1.2.3.18", 22, "SSH-1.99-OpenSSH_4.3"}, want{"SSH", "OpenSSH", "4.3", "", 0.95}},
		{"tls-clienthello", Record{"1.2.3.19", 9999, "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"}, want{"TLS", "", "", "", 0.6}},
		{"http-iis", Record{"1.2.3.20", 8888, "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"}, want{"HTTP", "Microsoft-IIS", "10.0", "", 0.9}},
		{"redis-noauth", Record{"1.2.3.21", 6379, "-NOAUTH Authentication required."}, want{"Redis", "Redis", "", "", 0.7}},
		{"ftp-pureftpd", Record{"1.2.3.22", 21, "220 Welcome to Pure-FTPd"}, want{"FTP", "Pure-FTPd", "", "", 0.7}},
		{"unknown-quit", Record{"1.2.3.23", 12345, "QUIT\r\n"}, want{"unknown", "", "", "", 0}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Identify(tc.in)
			if got.Protocol != tc.want.protocol || got.Product != tc.want.product ||
				got.Version != tc.want.version || got.OsHint != tc.want.osHint ||
				!approx(got.Confidence, tc.want.confidence) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestIdentifyUnknownNeverErrors(t *testing.T) {
	e := loadTestEngine(t)
	for _, banner := range []string{"", "garbage", "\x00\x01\x02", "QUIT\r\n", "unrecognizable text"} {
		got := e.Identify(Record{IP: "9.9.9.9", Port: 1, Banner: banner})
		if got.Protocol != "unknown" || got.Confidence != 0 {
			t.Fatalf("banner %q => %+v, want unknown", banner, got)
		}
	}
}
