package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nnv-nick/antiddos/cmd/antiddos/actuator"
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
	ctlDir := flag.String("ctl-dir", envOr("POSTFIX_CTL_DIR", "/postfix-ctl"), "Path to postfix-ctl directory")
	interval := flag.Duration("interval", 5*time.Second, "Detector poll interval")
	flag.Parse()

	log.Printf("antiddos: log=%s metricsURL=%s ctlDir=%s interval=%s", *logPath, *metricsURL, *ctlDir, *interval)

	detThresholds := detector.DefaultThresholds()
	actConfig := actuator.DefaultConfig()
	if *thresholdsPath != "" {
		t, err := detector.LoadFromFile(*thresholdsPath)
		if err != nil {
			log.Fatalf("antiddos: failed to load thresholds from %s: %v", *thresholdsPath, err)
		}
		detThresholds = t

		c, err := actuator.LoadConfigFromFile(*thresholdsPath)
		if err != nil {
			log.Fatalf("antiddos: failed to load actuator config from %s: %v", *thresholdsPath, err)
		}
		actConfig = c
		log.Printf("antiddos: loaded config from %s", *thresholdsPath)
	} else {
		log.Println("antiddos: using default thresholds and actuator config")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c := collector.NewWithHTTP(*logPath, *metricsURL)
	d := detector.New(detThresholds)
	a := actuator.New(*ctlDir, actConfig)

	go c.Run(ctx)

	time.Sleep(2 * time.Second)

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
			if err := a.Apply(dec, s); err != nil {
				log.Printf("actuator error: %v", err)
			}
		}
	}
}
