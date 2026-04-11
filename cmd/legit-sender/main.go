// legit-sender — непрерывно шлёт письма на Postfix и экспортирует метрики.
// Метрики позволяют измерить PDR (Protected Delivery Rate) под атакой.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

var (
	metricsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "legit_sender_sent_total",
		Help: "Total messages attempted",
	})
	metricsDelivered = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "legit_sender_delivered_total",
		Help: "Total messages accepted by Postfix (2xx)",
	})
	metricsRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "legit_sender_rejected_total",
		Help: "Total messages rejected by Postfix (4xx/5xx)",
	})
	metricsLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "legit_sender_latency_seconds",
		Help:    "End-to-end SMTP transaction latency",
		Buckets: prometheus.DefBuckets,
	})
)

func init() {
	prometheus.MustRegister(metricsSent, metricsDelivered, metricsRejected, metricsLatency)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

const (
	dialTimeout  = 3 * time.Second  // TCP connect timeout
	smtpDeadline = 6 * time.Second  // total SMTP transaction deadline after connect
	// 6s: normal transaction completes in <500ms, so plenty of margin.
	// Junk sessions hold slots for ~12s (3 free + 12×1s sleep),
	// so legit attempts that queue behind them will timeout → rejected.
)

func sendOne(addr, from, to string) error {
	start := time.Now()

	host, _, _ := net.SplitHostPort(addr)
	body := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: legit test\r\n\r\nlegit message at %s\r\n",
		from, to, time.Now().Format(time.RFC3339),
	)

	// Dial with explicit timeout — without this, SendMail hangs indefinitely
	// when all Postfix workers are busy (e.g. during slow_loris attack).
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		metricsSent.Inc()
		metricsRejected.Inc()
		return err
	}
	conn.SetDeadline(time.Now().Add(smtpDeadline))

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		metricsSent.Inc()
		metricsRejected.Inc()
		return err
	}
	defer c.Close()

	if err = c.Mail(from); err != nil {
		metricsSent.Inc()
		metricsRejected.Inc()
		return err
	}
	if err = c.Rcpt(to); err != nil {
		metricsSent.Inc()
		metricsRejected.Inc()
		return err
	}
	wc, err := c.Data()
	if err != nil {
		metricsSent.Inc()
		metricsRejected.Inc()
		return err
	}
	if _, err = fmt.Fprint(wc, body); err != nil {
		wc.Close()
		metricsSent.Inc()
		metricsRejected.Inc()
		return err
	}
	if err = wc.Close(); err != nil {
		metricsSent.Inc()
		metricsRejected.Inc()
		return err
	}
	c.Quit()

	elapsed := time.Since(start).Seconds()
	_ = host
	metricsSent.Inc()
	metricsDelivered.Inc()
	metricsLatency.Observe(elapsed)
	return nil
}

func main() {
	smtpHost := flag.String("smtp-host", envOr("SMTP_HOST", "localhost"), "Postfix host")
	smtpPort := flag.String("smtp-port", envOr("SMTP_PORT", "25"), "Postfix port")
	from := flag.String("from", envOr("FROM_ADDR", "legit@sender.test"), "MAIL FROM")
	to := flag.String("to", envOr("TO_ADDR", "user@test.local"), "RCPT TO")
	rateStr := flag.String("rate", envOr("RATE_PER_SEC", "2"), "messages per second")
	metricsAddr := flag.String("metrics-addr", envOr("METRICS_ADDR", ":9155"), "Prometheus metrics listen addr")
	flag.Parse()

	rate, err := strconv.ParseFloat(*rateStr, 64)
	if err != nil || rate <= 0 {
		log.Fatalf("invalid rate: %s", *rateStr)
	}

	smtpAddr := net.JoinHostPort(*smtpHost, *smtpPort)
	interval := time.Duration(float64(time.Second) / rate)

	log.Printf("legit-sender: smtp=%s from=%s to=%s rate=%.1f/s interval=%s metrics=%s",
		smtpAddr, *from, *to, rate, interval, *metricsAddr)

	// Запускаем HTTP-сервер метрик
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(*metricsAddr, nil); err != nil {
			log.Fatalf("metrics server: %v", err)
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		go func() {
			if err := sendOne(smtpAddr, *from, *to); err != nil {
				log.Printf("rejected: %v", err)
			}
		}()
	}
}
