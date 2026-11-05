package probe

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cenab/airgapproof/internal/report"
	"golang.org/x/net/dns/dnsmessage"
)

func DNSResponse(packet []byte) ([]byte, string, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(packet); err != nil {
		return nil, "", err
	}
	if len(msg.Questions) == 0 {
		return nil, "", io.ErrUnexpectedEOF
	}
	name := msg.Questions[0].Name.String()
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: msg.Header.ID, Response: true, RecursionDesired: msg.Header.RecursionDesired, RecursionAvailable: false, RCode: dnsmessage.RCodeNameError}, Questions: msg.Questions}
	b, err := response.Pack()
	return b, name, err
}
func ServeDNS(ctx context.Context, addr string, out io.Writer) error {
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer tcp.Close()
	go func() { <-ctx.Done(); _ = udp.Close(); _ = tcp.Close() }()
	var mu sync.Mutex
	count := 0
	encoder := json.NewEncoder(out)
	emit := func(src, name string) {
		mu.Lock()
		defer mu.Unlock()
		if count < 10000 {
			_ = encoder.Encode(report.Observation{Kind: "dns", Time: time.Now().UTC(), Source: src, Destination: name, Port: 53, External: true, Evidence: "DNS query received by the sandbox resolver; NXDOMAIN returned without forwarding"})
		}
		count++
		if count == 10001 {
			_ = encoder.Encode(map[string]string{"kind": "gap", "detail": "DNS observation limit reached"})
		}
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			b, name, err := DNSResponse(buf[:n])
			if err != nil {
				continue
			}
			host, _, _ := net.SplitHostPort(src.String())
			emit(host, name)
			_, _ = udp.WriteTo(b, src)
		}
	}()
	for {
		conn, err := tcp.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			var size [2]byte
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(size[:]))
			if n > 4096 {
				return
			}
			packet := make([]byte, n)
			if _, err := io.ReadFull(conn, packet); err != nil {
				return
			}
			b, name, err := DNSResponse(packet)
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			emit(host, name)
			binary.BigEndian.PutUint16(size[:], uint16(len(b)))
			_, _ = conn.Write(append(size[:], b...))
		}()
	}
}
