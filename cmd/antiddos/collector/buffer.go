package collector

import (
	"sync"
	"time"
)

type EventBuffer struct {
	mu        sync.Mutex
	events    []Event
	window    time.Duration
	lastDepth int
	hasDepth  bool
}

func NewEventBuffer(window time.Duration) *EventBuffer {
	return &EventBuffer{window: window}
}

func (b *EventBuffer) Add(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e.Type == EvQueueDepth {
		b.lastDepth = e.Depth
		b.hasDepth = true
		return
	}
	b.events = append(b.events, e)
}

func (b *EventBuffer) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.trim()

	secs := b.window.Seconds()
	var connects, disconnects, noqueue, timeouts int
	var wastedCmds int

	for _, e := range b.events {
		switch e.Type {
		case EvConnect:
			connects++
		case EvDisconnect:
			disconnects++
			if e.Mail == 0 && e.Commands > 0 {
				wastedCmds += e.Commands
			}
		case EvNoqueue:
			noqueue++
		case EvTimeout:
			timeouts++
		}
	}

	return Snapshot{
		ConnRate:       float64(connects) / secs,
		ActiveSessions: connects - disconnects,
		NoqueueRate:    float64(noqueue) / secs,
		TimeoutRate:    float64(timeouts) / secs,
		WastedCmdRate:  float64(wastedCmds) / secs,
		QueueDepth:     b.lastDepth,
		At:             time.Now(),
	}
}

func (b *EventBuffer) trim() {
	cutoff := time.Now().Add(-b.window)
	out := b.events[:0]
	for _, e := range b.events {
		if e.At.After(cutoff) {
			out = append(out, e)
		}
	}
	b.events = out
}
