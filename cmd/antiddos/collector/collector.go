package collector

import (
	"context"
	"time"
)

const defaultWindow = 30 * time.Second

type Collector struct {
	tailer *LogTailer
	poller *QueuePoller
	buf    *EventBuffer
}

func New(logPath, postqueueBin string) *Collector {
	buf := NewEventBuffer(defaultWindow)
	return &Collector{
		buf:    buf,
		tailer: NewLogTailer(logPath, buf),
		poller: NewQueuePollerExec(postqueueBin, 5*time.Second, buf),
	}
}

func NewWithHTTP(logPath, metricsURL string) *Collector {
	buf := NewEventBuffer(defaultWindow)
	return &Collector{
		buf:    buf,
		tailer: NewLogTailer(logPath, buf),
		poller: NewQueuePollerHTTP(metricsURL, 5*time.Second, buf),
	}
}

func (c *Collector) Run(ctx context.Context) {
	go c.poller.Run(ctx)
	c.tailer.Run(ctx)
}

func (c *Collector) Snapshot() Snapshot {
	return c.buf.Snapshot()
}
