package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/inventory"
)

// scanInterface is a synthetic interface; injected runners never use its network.
func scanInterface() network.Interface {
	return network.Interface{Name: "fixture", Up: true, Multicast: true, IPv4: []string{"192.0.2.10/24"}}
}

func awaitScan(t *testing.T, m *Manager, id string) State {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		_, notify, done, _, ok := m.Events(id, 0)
		if !ok {
			t.Fatal("missing scan")
		}
		if done {
			state, _ := m.State(id)
			return state
		}
		select {
		case <-notify:
		case <-deadline.C:
			t.Fatal("scan did not complete")
		}
	}
}

func TestManagerCancellationAndIsolation(t *testing.T) {
	started := make(chan struct{})
	manager := NewManager(context.Background(), func(ctx context.Context, _ network.Interface, _ time.Duration, _ bool, emit func(string, any), update func([]inventory.Device)) (Report, error) {
		devices := []inventory.Device{{ID: "fixture", Attributes: map[string]string{"friendly_name": "fixture"}}}
		update(devices)
		emit("host-found", map[string]string{"ip": "192.0.2.20"})
		close(started)
		<-ctx.Done()
		return Report{Devices: devices, Warnings: []Warning{}}, ctx.Err()
	})
	defer manager.Close()
	id, err := manager.Start(scanInterface(), time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := manager.Start(scanInterface(), time.Second, true); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	snapshot, _ := manager.State(id)
	snapshot.Report.Devices[0].Attributes["friendly_name"] = "mutated"
	current, _ := manager.State(id)
	if current.Report.Devices[0].Attributes["friendly_name"] != "fixture" {
		t.Fatal("snapshot aliases manager")
	}
	events, _, _, _, _ := manager.Events(id, 0)
	events[0].Data[0] = '!'
	events, _, _, _, _ = manager.Events(id, 0)
	if events[0].Data[0] == '!' {
		t.Fatal("event aliases manager")
	}
	if !manager.Cancel(id) {
		t.Fatal("cancel failed")
	}
	final := awaitScan(t, manager, id)
	if final.Status != "cancelled" || len(final.Report.Devices) != 1 {
		t.Fatal(final)
	}
	manager.Close()
	if _, err := manager.Start(scanInterface(), time.Second, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestManagerReplayAndRetention(t *testing.T) {
	manager := NewManager(context.Background(), func(_ context.Context, _ network.Interface, _ time.Duration, _ bool, emit func(string, any), _ func([]inventory.Device)) (Report, error) {
		for i := 0; i < 600; i++ {
			emit("host-found", i)
		}
		return Report{Devices: []inventory.Device{}, Warnings: []Warning{}}, nil
	})
	defer manager.Close()
	first := ""
	for i := 0; i < 9; i++ {
		id, err := manager.Start(scanInterface(), time.Second, false)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = id
		}
		if state := awaitScan(t, manager, id); state.Status != "completed" {
			t.Fatal(state)
		}
		events, _, done, reset, ok := manager.Events(id, 0)
		if !ok || !done || !reset || len(events) != 512 || events[len(events)-1].Type != "scan-complete" {
			t.Fatal("invalid bounded journal")
		}
		replay, _, _, reset, _ := manager.Events(id, events[len(events)-2].ID)
		if reset || len(replay) != 1 {
			t.Fatal("replay failed")
		}
	}
	if _, ok := manager.State(first); ok {
		t.Fatal("expired session retained")
	}
	if _, err := manager.Start(scanInterface(), 0, false); err == nil {
		t.Fatal("invalid duration accepted")
	}
}

func TestManagerShutdownCancelsActiveWork(t *testing.T) {
	manager := NewManager(context.Background(), func(ctx context.Context, _ network.Interface, _ time.Duration, _ bool, _ func(string, any), _ func([]inventory.Device)) (Report, error) {
		<-ctx.Done()
		return Report{Devices: []inventory.Device{}, Warnings: []Warning{}}, ctx.Err()
	})
	id, err := manager.Start(scanInterface(), time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { manager.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not join cancelled runner")
	}
	if state, ok := manager.State(id); !ok || state.Status != "cancelled" {
		t.Fatal(state)
	}
}
