package tools

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "fixture-tool")
	if err := os.WriteFile(binary, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	got := Discover("fixture-tool", "missing-tool")
	if len(got) != 2 || !got[0].Available || got[0].Path != binary || got[1].Available {
		t.Fatalf("unexpected tools: %+v", got)
	}
}
