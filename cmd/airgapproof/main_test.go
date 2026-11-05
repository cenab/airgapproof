package main

import (
	"bytes"
	"testing"
)

func TestCLIRejectsUnknownAndMissingFlags(t *testing.T) {
	for _, args := range [][]string{{"test", "--unknown"}, {"bundle", "export"}, {"verify", "report.json"}, {"patch-model"}} {
		cmd := root()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if cmd.Execute() == nil {
			t.Fatal(args)
		}
	}
}
