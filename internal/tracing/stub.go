//go:build !linux

package tracing

import (
	"context"
	"errors"
	"io"
)

func Run(context.Context, io.Writer) error { return errors.New("eBPF tracing requires Linux") }
