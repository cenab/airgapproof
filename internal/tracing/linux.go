//go:build linux

package tracing

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cenab/airgapproof/internal/report"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type event struct {
	Cgroup  uint64
	Result  int64
	PID     uint32
	Family  uint16
	Port    uint16
	Address [16]byte
	Comm    [16]byte
	Kind    uint32
	Padding uint32
}

var containerPattern = regexp.MustCompile(`[a-f0-9]{64}`)

func Run(ctx context.Context, out io.Writer) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	data, err := os.ReadFile("/trace.bpf.o")
	if err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF: %w", err)
	}
	defer collection.Close()
	for _, p := range []struct{ program, hook string }{{"connect_enter", "sys_enter_connect"}, {"connect_exit", "sys_exit_connect"}, {"sendto_enter", "sys_enter_sendto"}, {"sendto_exit", "sys_exit_sendto"}} {
		l, err := link.Tracepoint("syscalls", p.hook, collection.Programs[p.program], nil)
		if err != nil {
			return err
		}
		defer l.Close()
	}
	r, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		return err
	}
	defer r.Close()
	go func() { <-ctx.Done(); _ = r.Close() }()
	enc := json.NewEncoder(out)
	if err = enc.Encode(map[string]string{"kind": "ready"}); err != nil {
		return err
	}
	var targets []string
	if err = json.Unmarshal([]byte(os.Getenv("AIRGAPPROOF_TARGETS")), &targets); err != nil || len(targets) == 0 {
		return fmt.Errorf("tracer requires explicit target container IDs")
	}
	cache := map[uint64]string{}
	count := 0
	unattributed := 0
	for {
		record, err := r.Read()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return err
		}
		var e event
		if err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			return err
		}
		container := cache[e.Cgroup]
		if container == "" {
			b, _ := os.ReadFile(filepath.Join("/host/proc", fmt.Sprint(e.PID), "cgroup"))
			matches := containerPattern.FindAllString(string(b), -1)
			allowed := false
			for _, match := range matches {
				for _, target := range targets {
					if match == target {
						allowed = true
					}
				}
			}
			if len(matches) > 0 && allowed {
				container = matches[len(matches)-1]
			} else if len(matches) > 0 {
				container = "ignore"
			}
			if container != "" {
				cache[e.Cgroup] = container
			}
		}
		if container == "ignore" {
			continue
		}
		if container == "" {
			unattributed++
			continue
		}
		if count >= 30000 {
			continue
		}
		count++
		ip := net.IP(e.Address[:])
		if e.Family == 2 {
			ip = net.IP(e.Address[:4])
		}
		kind := "connect"
		if e.Kind == 2 {
			kind = "sendto"
		}
		obs := report.Observation{Kind: kind, Time: time.Now().UTC(), Container: container, PID: e.PID, Process: strings.TrimRight(string(e.Comm[:]), "\x00"), Destination: ip.String(), Port: e.Port, Result: e.Result, Evidence: "Linux syscall tracepoint recorded destination and return code; connect can also represent connected UDP"}
		if err = enc.Encode(obs); err != nil {
			return err
		}
	}
	var dropped uint64
	key := uint32(0)
	_ = collection.Maps["dropped"].Lookup(&key, &dropped)
	if dropped > 0 || count >= 30000 || unattributed > 0 {
		_ = enc.Encode(map[string]any{"kind": "gap", "detail": fmt.Sprintf("Tracer loss: ring=%d, observation_limit=%t, unattributed_host_events=%d", dropped, count >= 30000, unattributed)})
	}
	return nil
}
