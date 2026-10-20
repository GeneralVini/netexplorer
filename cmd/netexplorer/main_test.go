package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestCommands(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &output, io.Discard); err != nil || !strings.Contains(output.String(), version) {
		t.Fatalf("version: %s %v", output.String(), err)
	}
	for _, args := range [][]string{{"scan", "--timeout", "0s"}, {"version", "extra"}, {"serve", "--listen", ":8080"}} {
		if err := run(context.Background(), args, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if err := run(context.Background(), []string{"scan", "--help"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}
