package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cenab/airgapproof/internal/config"
	"github.com/cenab/airgapproof/internal/probe"
	"github.com/cenab/airgapproof/internal/tracing"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "dns":
		err = probe.ServeDNS(ctx, ":53", os.Stdout)
	case "http":
		var s config.Scenario
		if err = json.NewDecoder(os.Stdin).Decode(&s); err == nil {
			ctx, cancel := context.WithTimeout(ctx, s.Duration())
			defer cancel()
			result := probe.HTTP(ctx, s)
			err = json.NewEncoder(os.Stdout).Encode(result)
			if !result.Passed {
				os.Exit(1)
			}
		}
	case "canary":
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if len(os.Args) < 3 || os.Args[2] != "egress-only" {
			err = probe.NoDefaultRoute()
		}
		if err == nil {
			err = probe.EgressBlocked(ctx)
		}
	case "trace":
		err = tracing.Run(ctx, os.Stdout)
	default:
		err = fmt.Errorf("unknown helper operation")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
