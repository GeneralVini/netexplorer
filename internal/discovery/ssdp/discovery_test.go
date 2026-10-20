package ssdp

import (
	"context"
	"errors"
	"net"
	"netexplorer/internal/discovery/network"
	"strings"
	"testing"
	"time"
)

func localSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestExchange(t *testing.T) {
	responder := localSocket(t)
	client := localSocket(t)
	_, subnet, _ := net.ParseCIDR("127.0.0.0/8")
	failures := make(chan error, 1)
	go func() {
		responder.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 2048)
		n, source, err := responder.ReadFromUDP(buffer)
		if err != nil {
			failures <- err
			return
		}
		if string(buffer[:n]) != searchMessage {
			failures <- errors.New("incorrect M-SEARCH")
			return
		}
		valid := "HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1/root.xml\r\nUSN: uuid:test\r\nST: upnp:rootdevice\r\n\r\n"
		for _, response := range []string{"invalid", valid, valid, strings.Replace(valid, "upnp:rootdevice", "urn:test:service", 1)} {
			if _, err := responder.WriteToUDP([]byte(response), source); err != nil {
				failures <- err
				return
			}
		}
		failures <- nil
	}()
	results, err := exchange(context.Background(), client, responder.LocalAddr().(*net.UDPAddr), subnet, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-failures; err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].IP != "127.0.0.1" || results[0].SeenAt.IsZero() {
		t.Fatalf("responses: %+v", results)
	}
}

func TestExchangeCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			client := localSocket(t)
			responder := localSocket(t)
			_, subnet, _ := net.ParseCIDR("127.0.0.0/8")
			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
				want = context.DeadlineExceeded
			} else {
				timer := time.AfterFunc(30*time.Millisecond, cancel)
				defer timer.Stop()
			}
			defer cancel()
			start := time.Now()
			_, err := exchange(ctx, client, responder.LocalAddr().(*net.UDPAddr), subnet, time.Second)
			if !errors.Is(err, want) {
				t.Fatalf("expected %v, got %v", want, err)
			}
			if time.Since(start) > 500*time.Millisecond {
				t.Fatal("cancellation was too slow")
			}
		})
	}
}

func TestExchangeRejectsOutsideSubnet(t *testing.T) {
	responder := localSocket(t)
	client := localSocket(t)
	_, subnet, _ := net.ParseCIDR("192.0.2.0/24")
	go func() {
		responder.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 1024)
		_, source, err := responder.ReadFromUDP(buffer)
		if err == nil {
			responder.WriteToUDP([]byte("HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1/root.xml\r\nUSN: uuid:test\r\nST: ssdp:all\r\n\r\n"), source)
		}
	}()
	results, err := exchange(context.Background(), client, responder.LocalAddr().(*net.UDPAddr), subnet, 100*time.Millisecond)
	if err != nil || len(results) != 0 {
		t.Fatalf("accepted outside subnet: %+v %v", results, err)
	}
}

func TestDiscoverValidation(t *testing.T) {
	if _, err := Discover(context.Background(), network.Interface{}, 0); err == nil {
		t.Fatal("accepted zero duration")
	}
	if _, err := Discover(context.Background(), network.Interface{}, time.Second); err == nil {
		t.Fatal("accepted invalid interface")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Discover(ctx, network.Interface{}, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestExchangeExcludesLocalSourcesBeforeProgress(t *testing.T) {
	client := localSocket(t)
	responder := localSocket(t)
	aliases := make([]*net.UDPConn, 0, 2)
	for _, address := range []string{"127.0.0.2", "127.0.0.3"} {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(address)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		aliases = append(aliases, conn)
	}
	failures := make(chan error, 1)
	go func() {
		if err := responder.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			failures <- err
			return
		}
		buffer := make([]byte, 1024)
		_, source, err := responder.ReadFromUDP(buffer)
		if err != nil {
			failures <- err
			return
		}
		packet := []byte("HTTP/1.1 200 OK\r\nLOCATION: http://fixture.invalid/root.xml\r\nUSN: uuid:fixture\r\nST: upnp:rootdevice\r\n\r\n")
		for _, socket := range append([]*net.UDPConn{responder}, aliases...) {
			if _, err := socket.WriteToUDP(packet, source); err != nil {
				failures <- err
				return
			}
		}
		failures <- nil
	}()
	_, subnet, _ := net.ParseCIDR("127.0.0.0/8")
	observed := []Response{}
	results, err := exchangeProgress(context.Background(), client, responder.LocalAddr().(*net.UDPAddr), subnet, 100*time.Millisecond, func(r Response) { observed = append(observed, r) }, map[string]bool{"127.0.0.1": true, "127.0.0.2": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-failures; err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].IP != "127.0.0.3" || len(observed) != 1 || observed[0].IP != "127.0.0.3" {
		t.Fatalf("local evidence leaked: results=%+v progress=%+v", results, observed)
	}
}
