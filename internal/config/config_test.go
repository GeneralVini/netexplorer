package config

import (
	"io"
	"testing"
)

func TestParse(t *testing.T) {
	t.Setenv("NETEXPLORER_LISTEN", "127.0.0.1:9090")
	t.Setenv("NETEXPLORER_INTERFACE", "eth-test")
	c, err := Parse([]string{"--listen", "127.0.0.1:8081"}, io.Discard)
	if err != nil || c.Listen != "127.0.0.1:8081" || c.Interface != "eth-test" {
		t.Fatalf("unexpected configuration: %+v %v", c, err)
	}
	for _, args := range [][]string{{"--listen", ":8080"}, {"--listen", "localhost:0"}, {"extra"}, {"--unknown"}} {
		if _, err := Parse(args, io.Discard); err == nil {
			t.Fatalf("accepted invalid args: %v", args)
		}
	}
}
