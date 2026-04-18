package collector

import (
	"context"
	"time"
)

const defaultWindow = 30 * time.Second

// Collector объединяет LogTailer и QueuePoller в единый источник Snapshot.
type Collector struct {
	tailer *LogTailer
	poller *QueuePoller
	buf    *EventBuffer
}

// New создаёт Collector для запуска на том же хосте, что и Postfix.
//   - logPath      — путь к mail.log
//   - postqueueBin — путь к бинарю postqueue (например "/usr/sbin/postqueue")
func New(logPath, postqueueBin string) *Collector {
	buf := NewEventBuffer(defaultWindow)
	return &Collector{
		buf:    buf,
		tailer: NewLogTailer(logPath, buf),
		poller: NewQueuePollerExec(postqueueBin, 5*time.Second, buf),
	}
}

// NewWithHTTP создаёт Collector для контейнерного окружения.
// Глубина очереди читается из метрик postfix-exporter по HTTP.
//   - logPath    — путь к mail.log (через shared volume)
//   - metricsURL — URL метрик postfix-exporter, например "http://postfix-exporter:9154/metrics"
func NewWithHTTP(logPath, metricsURL string) *Collector {
	buf := NewEventBuffer(defaultWindow)
	return &Collector{
		buf:    buf,
		tailer: NewLogTailer(logPath, buf),
		poller: NewQueuePollerHTTP(metricsURL, 5*time.Second, buf),
	}
}

// Run запускает тейлер и poller. Блокирует до отмены ctx.
func (c *Collector) Run(ctx context.Context) {
	go c.poller.Run(ctx)
	c.tailer.Run(ctx) // tails log in current goroutine
}

// Snapshot возвращает текущие агрегаты за скользящее окно.
func (c *Collector) Snapshot() Snapshot {
	return c.buf.Snapshot()
}
