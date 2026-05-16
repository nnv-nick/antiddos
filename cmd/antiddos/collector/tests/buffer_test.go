package collector_test

import (
	"testing"
	"time"

	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
)

func TestBufferEmptySnapshot(t *testing.T) {
	buf := collector.NewEventBuffer(30 * time.Second)
	s := buf.Snapshot()
	if s.ConnRate != 0 || s.ActiveSessions != 0 || s.NoqueueRate != 0 ||
		s.TimeoutRate != 0 || s.WastedCmdRate != 0 || s.QueueDepth != 0 {
		t.Errorf("empty buffer returned non-zero snapshot: %+v", s)
	}
}

func TestBufferConnRate(t *testing.T) {
	window := 10 * time.Second
	buf := collector.NewEventBuffer(window)
	now := time.Now()

	for i := 0; i < 5; i++ {
		buf.Add(collector.Event{At: now.Add(-time.Duration(i) * time.Second), Type: collector.EvConnect})
	}
	buf.Add(collector.Event{At: now.Add(-20 * time.Second), Type: collector.EvConnect})

	s := buf.Snapshot()
	want := 5.0 / window.Seconds()
	if s.ConnRate != want {
		t.Errorf("ConnRate = %.4f, want %.4f", s.ConnRate, want)
	}
}

func TestBufferActiveSessions(t *testing.T) {
	buf := collector.NewEventBuffer(30 * time.Second)
	now := time.Now()

	buf.Add(collector.Event{At: now.Add(-5 * time.Second), Type: collector.EvConnect})
	buf.Add(collector.Event{At: now.Add(-5 * time.Second), Type: collector.EvConnect})
	buf.Add(collector.Event{At: now.Add(-5 * time.Second), Type: collector.EvConnect})
	buf.Add(collector.Event{At: now.Add(-3 * time.Second), Type: collector.EvDisconnect, Commands: 5, Mail: 1})

	s := buf.Snapshot()
	if s.ActiveSessions != 2 {
		t.Errorf("ActiveSessions = %d, want 2", s.ActiveSessions)
	}
}

func TestBufferNoqueueRate(t *testing.T) {
	window := 10 * time.Second
	buf := collector.NewEventBuffer(window)
	now := time.Now()

	for i := 0; i < 3; i++ {
		buf.Add(collector.Event{At: now.Add(-time.Duration(i) * time.Second), Type: collector.EvNoqueue})
	}

	s := buf.Snapshot()
	want := 3.0 / window.Seconds()
	if s.NoqueueRate != want {
		t.Errorf("NoqueueRate = %.4f, want %.4f", s.NoqueueRate, want)
	}
}

func TestBufferTimeoutRate(t *testing.T) {
	window := 10 * time.Second
	buf := collector.NewEventBuffer(window)
	now := time.Now()

	buf.Add(collector.Event{At: now.Add(-1 * time.Second), Type: collector.EvTimeout})
	buf.Add(collector.Event{At: now.Add(-2 * time.Second), Type: collector.EvTimeout})

	s := buf.Snapshot()
	want := 2.0 / window.Seconds()
	if s.TimeoutRate != want {
		t.Errorf("TimeoutRate = %.4f, want %.4f", s.TimeoutRate, want)
	}
}

func TestBufferWastedCmdRate(t *testing.T) {
	window := 10 * time.Second
	buf := collector.NewEventBuffer(window)
	now := time.Now()

	buf.Add(collector.Event{At: now.Add(-1 * time.Second), Type: collector.EvDisconnect, Commands: 15, Mail: 0})
	buf.Add(collector.Event{At: now.Add(-2 * time.Second), Type: collector.EvDisconnect, Commands: 5, Mail: 1})
	buf.Add(collector.Event{At: now.Add(-3 * time.Second), Type: collector.EvDisconnect, Commands: 50, Mail: 0})

	s := buf.Snapshot()
	want := (15.0 + 50.0) / window.Seconds()
	if s.WastedCmdRate != want {
		t.Errorf("WastedCmdRate = %.4f, want %.4f", s.WastedCmdRate, want)
	}
}

func TestBufferWastedCmdZeroCommands(t *testing.T) {
	buf := collector.NewEventBuffer(30 * time.Second)
	buf.Add(collector.Event{At: time.Now(), Type: collector.EvDisconnect, Commands: 0, Mail: 0})

	s := buf.Snapshot()
	if s.WastedCmdRate != 0 {
		t.Errorf("WastedCmdRate = %.4f, want 0 for commands=0", s.WastedCmdRate)
	}
}

func TestBufferQueueDepth(t *testing.T) {
	buf := collector.NewEventBuffer(30 * time.Second)

	buf.Add(collector.Event{At: time.Now(), Type: collector.EvQueueDepth, Depth: 42})
	s := buf.Snapshot()
	if s.QueueDepth != 42 {
		t.Errorf("QueueDepth = %d, want 42", s.QueueDepth)
	}

	buf.Add(collector.Event{At: time.Now(), Type: collector.EvQueueDepth, Depth: 7})
	s = buf.Snapshot()
	if s.QueueDepth != 7 {
		t.Errorf("QueueDepth = %d, want 7 after update", s.QueueDepth)
	}
}

func TestBufferQueueDepthNotCountedInRates(t *testing.T) {
	buf := collector.NewEventBuffer(30 * time.Second)
	buf.Add(collector.Event{At: time.Now(), Type: collector.EvQueueDepth, Depth: 10})

	s := buf.Snapshot()
	if s.ConnRate != 0 || s.WastedCmdRate != 0 {
		t.Errorf("EvQueueDepth polluted rate metrics: %+v", s)
	}
}

func TestBufferTrimExpiredEvents(t *testing.T) {
	window := 5 * time.Second
	buf := collector.NewEventBuffer(window)
	now := time.Now()

	buf.Add(collector.Event{At: now.Add(-10 * time.Second), Type: collector.EvConnect})
	buf.Add(collector.Event{At: now.Add(-1 * time.Second), Type: collector.EvConnect})

	s := buf.Snapshot()
	want := 1.0 / window.Seconds()
	if s.ConnRate != want {
		t.Errorf("ConnRate = %.4f, want %.4f (expired event not trimmed)", s.ConnRate, want)
	}
}
