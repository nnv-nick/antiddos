package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// reQueueEntry соответствует строкам с ID сообщения в выводе postqueue -p.
var reQueueEntry = regexp.MustCompile(`(?m)^[A-F0-9]{10,}[* ]\s`)

// reQueueDepthMetric находит значение postfix_queue_depth в Prometheus text format.
var reQueueDepthMetric = regexp.MustCompile(`(?m)^postfix_queue_depth\s+(\S+)`)

// QueuePoller периодически запрашивает глубину очереди и кладёт результат
// в буфер как EvQueueDepth. Способ получения задаётся через depthFn.
type QueuePoller struct {
	depthFn  func() (int, error)
	interval time.Duration
	buf      *EventBuffer
}

// NewQueuePollerExec создаёт poller, запускающий postqueue напрямую.
// Используется когда antiddos запущен на том же хосте, что и Postfix.
func NewQueuePollerExec(bin string, interval time.Duration, buf *EventBuffer) *QueuePoller {
	return &QueuePoller{
		interval: interval,
		buf:      buf,
		depthFn: func() (int, error) {
			out, err := exec.Command(bin, "-p").Output()
			if err != nil {
				return 0, fmt.Errorf("postqueue: %w", err)
			}
			return CountQueued(string(out)), nil
		},
	}
}

// NewQueuePollerHTTP создаёт poller, читающий глубину очереди из метрик
// postfix-exporter по HTTP. Используется в контейнерном окружении.
func NewQueuePollerHTTP(metricsURL string, interval time.Duration, buf *EventBuffer) *QueuePoller {
	client := &http.Client{Timeout: 3 * time.Second}
	return &QueuePoller{
		interval: interval,
		buf:      buf,
		depthFn:  func() (int, error) { return fetchQueueDepth(client, metricsURL) },
	}
}

// Run запускает цикл опроса. Блокирует до отмены ctx.
func (p *QueuePoller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.poll()
		}
	}
}

func (p *QueuePoller) poll() {
	depth, err := p.depthFn()
	if err != nil {
		log.Printf("collector/poller: %v", err)
		return
	}
	p.buf.Add(Event{At: time.Now(), Type: EvQueueDepth, Depth: depth})
}

// fetchQueueDepth читает /metrics с postfix-exporter и парсит postfix_queue_depth.
func fetchQueueDepth(client *http.Client, url string) (int, error) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read body: %w", err)
	}

	m := reQueueDepthMetric.FindSubmatch(body)
	if m == nil {
		return 0, nil // метрика ещё не появилась (нет писем) — 0
	}
	v, err := strconv.ParseFloat(string(m[1]), 64)
	if err != nil {
		return 0, fmt.Errorf("parse postfix_queue_depth %q: %w", m[1], err)
	}
	if v < 0 {
		return 0, nil // gauge может уйти в минус при рестарте exporter'а
	}
	return int(v), nil
}

// ParseQueueDepthFromMetrics парсит значение postfix_queue_depth из Prometheus
// text format. Экспортируется для тестирования.
func ParseQueueDepthFromMetrics(body string) (int, bool) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "postfix_queue_depth") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			continue
		}
		if v < 0 {
			return 0, true
		}
		return int(v), true
	}
	return 0, false
}

// CountQueued подсчитывает число сообщений в выводе "postqueue -p".
// Экспортируется для тестирования.
func CountQueued(out string) int {
	if strings.Contains(out, "Mail queue is empty") {
		return 0
	}
	return len(reQueueEntry.FindAllString(out, -1))
}
