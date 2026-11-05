package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cenab/airgapproof/internal/config"
)

type Result struct {
	Passed     bool   `json:"passed"`
	Status     int    `json:"status,omitempty"`
	BodySHA256 string `json:"body_sha256,omitempty"`
	Detail     string `json:"detail"`
}

func HTTP(ctx context.Context, s config.Scenario) Result {
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	var last Result
	for {
		req, err := http.NewRequestWithContext(ctx, s.Method, s.URL, strings.NewReader(s.Body))
		if err != nil {
			return Result{Detail: "invalid HTTP request"}
		}
		for k, v := range s.Headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			last = Result{Detail: "HTTP connection failed or timed out"}
		} else {
			b, readErr := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
			_ = resp.Body.Close()
			hash := sha256.Sum256(b)
			last = Result{Status: resp.StatusCode, BodySHA256: hex.EncodeToString(hash[:]), Detail: "HTTP status or response assertion did not match"}
			if readErr == nil && len(b) <= 1<<20 && resp.StatusCode == s.ExpectedStatus && strings.Contains(string(b), s.ExpectedContains) {
				last.Passed = true
				last.Detail = "HTTP status and response assertions passed"
				return last
			}
		}
		if s.Method != "GET" && s.Method != "HEAD" {
			return last
		}
		select {
		case <-ctx.Done():
			return last
		case <-time.After(250 * time.Millisecond):
		}
	}
}
func NoDefaultRoute() error {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 3 && f[0] != "lo" && f[1] == "00000000" {
			return errors.New("sandbox has an IPv4 default route")
		}
	}
	b, err = os.ReadFile("/proc/net/ipv6_route")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 9 && f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[9] != "lo" {
			return errors.New("sandbox has an IPv6 default route")
		}
	}
	return nil
}
func EgressBlocked(ctx context.Context) error {
	for _, addr := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443"} {
		d := net.Dialer{Timeout: 350 * time.Millisecond}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return errors.New("external TCP connection succeeded")
		}
	}
	return nil
}
