package run

import (
	"net/netip"
	"testing"
)

func TestInternalAddressesIncludeLocalUnspecifiedSockets(t *testing.T) {
	addresses := map[string]bool{"172.20.0.2": true}
	for _, ip := range []string{"127.0.0.1", "::1", "0.0.0.0", "::", "172.20.0.2"} {
		if !InternalDestination(ip, addresses, nil) {
			t.Errorf("local address classified as external: %s", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if InternalDestination(ip, addresses, nil) {
			t.Errorf("external address classified as internal: %s", ip)
		}
	}
}
func TestClusterRangesAreInternal(t *testing.T) {
	ranges := []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16"), netip.MustParsePrefix("10.96.0.0/16")}
	if !InternalDestination("10.244.0.4", nil, ranges) || !InternalDestination("10.96.0.10", nil, ranges) || InternalDestination("1.1.1.1", nil, ranges) {
		t.Fatal("incorrect cluster classification")
	}
}
