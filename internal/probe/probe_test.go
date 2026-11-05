package probe

import (
	"context"
	"github.com/cenab/airgapproof/internal/config"
	"golang.org/x/net/dns/dnsmessage"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPChecksBodyAndDoesNotRepeatPOST(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(201)
		_, _ = w.Write([]byte("processed"))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := config.Scenario{URL: srv.URL, Method: "POST", ExpectedStatus: 201, ExpectedContains: "processed"}
	if !HTTP(ctx, s).Passed {
		t.Fatal("expected success")
	}
	s.ExpectedStatus = 200
	if HTTP(ctx, s).Passed {
		t.Fatal("wrong status passed")
	}
	if calls.Load() != 2 {
		t.Fatal("POST was retried")
	}
}
func TestHTTPDoesNotFollowRedirect(t *testing.T) {
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r := HTTP(ctx, config.Scenario{URL: srv.URL, Method: "GET", ExpectedStatus: 200})
	if r.Passed || reached.Load() {
		t.Fatal("redirect followed")
	}
}
func TestDNSResponseNeverForwards(t *testing.T) {
	name, _ := dnsmessage.NewName("models.example.invalid.")
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: 123, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	b, _ := request.Pack()
	reply, got, err := DNSResponse(b)
	if err != nil || got != name.String() {
		t.Fatal(got, err)
	}
	var m dnsmessage.Message
	if err = m.Unpack(reply); err != nil {
		t.Fatal(err)
	}
	if !m.Response || m.ID != 123 || m.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
		t.Fatal("incorrect DNS denial")
	}
	if _, _, err = DNSResponse([]byte{0, 1}); err == nil {
		t.Fatal("malformed DNS accepted")
	}
}
