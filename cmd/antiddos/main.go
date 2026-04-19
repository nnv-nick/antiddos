// antiddos — защитный сервис для Postfix.
// Собирает метрики активности (collector), обнаруживает атаки (detector)
// и применяет защитные меры (actuator).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
	"github.com/nnv-nick/antiddos/cmd/antiddos/detector"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	logPath := flag.String("log", envOr("POSTFIX_LOG", "/var/log/mail.log"), "Path to Postfix mail.log")
	metricsURL := flag.String("metrics-url", envOr("EXPORTER_METRICS_URL", "http://postfix-exporter:9154/metrics"), "postfix-exporter metrics URL")
	thresholdsPath := flag.String("thresholds", envOr("THRESHOLDS_PATH", ""), "Path to thresholds YAML (optional, uses defaults if empty)")
	interval := flag.Duration("interval", 5*time.Second, "Detector poll interval")
	flag.Parse()

	log.Printf("antiddos: log=%s metricsURL=%s interval=%s", *logPath, *metricsURL, *interval)

	// Загружаем пороги
	thresholds := detector.DefaultThresholds()
	if *thresholdsPath != "" {
		t, err := detector.LoadFromFile(*thresholdsPath)
		if err != nil {
			log.Fatalf("antiddos: failed to load thresholds from %s: %v", *thresholdsPath, err)
		}
		thresholds = t
		log.Printf("antiddos: loaded thresholds from %s", *thresholdsPath)
	} else {
		log.Println("antiddos: using default thresholds")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c := collector.NewWithHTTP(*logPath, *metricsURL)
	d := detector.New(thresholds)

	// Запускаем collector в фоне
	go c.Run(ctx)

	// Ждём первых данных
	time.Sleep(2 * time.Second)

	// TODO: заменить заглушку на реальный actuator
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Println("antiddos: shutting down")
			return
		case <-ticker.C:
			s := c.Snapshot()
			dec := d.Analyze(s)
			log.Printf("snapshot: conn_rate=%.2f/s active=%d noqueue=%.2f/s timeout=%.2f/s wasted_cmd=%.2f/s queue=%d | decision: attack=%s severity=%s",
				s.ConnRate, s.ActiveSessions, s.NoqueueRate,
				s.TimeoutRate, s.WastedCmdRate, s.QueueDepth,
				dec.Attack, dec.Severity)
			// TODO: actuator.Apply(dec)
		}
	}
}
