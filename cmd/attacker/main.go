// attacker — генератор нагрузки для тестирования Postfix.
// Читает сценарий из YAML-файла и последовательно выполняет фазы.
// Каждая фаза запускает N воркеров с заданным типом атаки и rate.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

var (
	metricsAttackConnections = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "attacker_connections_total",
		Help: "Total TCP connections opened by attacker",
	})
	metricsAttackMessages = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "attacker_messages_total",
		Help: "Total SMTP commands/messages sent by attacker",
	})
	metricsPhase = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "attacker_phase",
		Help: "Current scenario phase index (0-based)",
	})
)

func init() {
	prometheus.MustRegister(metricsAttackConnections, metricsAttackMessages, metricsPhase)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	scenarioFile := flag.String("scenario", "", "Path to scenario YAML file")
	smtpHost := flag.String("smtp-host", envOr("SMTP_HOST", "localhost"), "Postfix host")
	smtpPort := flag.String("smtp-port", envOr("SMTP_PORT", "25"), "Postfix port")
	metricsAddr := flag.String("metrics-addr", envOr("METRICS_ADDR", ":9156"), "Prometheus metrics addr")
	flag.Parse()

	if *scenarioFile == "" {
		log.Fatal("--scenario is required")
	}

	data, err := os.ReadFile(*scenarioFile)
	if err != nil {
		log.Fatalf("read scenario: %v", err)
	}
	var scenario Scenario
	if err := yaml.Unmarshal(data, &scenario); err != nil {
		log.Fatalf("parse scenario: %v", err)
	}

	smtpAddr := *smtpHost + ":" + *smtpPort

	log.Printf("scenario: %s", scenario.Name)
	log.Printf("description: %s", scenario.Description)
	log.Printf("phases: %d", len(scenario.Phases))

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(*metricsAddr, nil); err != nil {
			log.Fatalf("metrics server: %v", err)
		}
	}()

	for i, phase := range scenario.Phases {
		metricsPhase.Set(float64(i))
		log.Printf("[phase %d/%d] %s — duration=%s type=%s workers=%d rate=%.1f/s",
			i+1, len(scenario.Phases),
			phase.Name, phase.Duration,
			phase.Attack.Type, phase.Attack.Workers, phase.Attack.RatePerSec,
		)
		runPhase(phase, smtpAddr)
		log.Printf("[phase %d/%d] done", i+1, len(scenario.Phases))
	}

	log.Printf("scenario %q completed", scenario.Name)
}

// runPhase запускает воркеры для одной фазы и ждёт её завершения.
func runPhase(phase Phase, smtpAddr string) {
	if phase.Attack.Type == "no_attack" {
		log.Printf("  no attack — waiting %s", phase.Duration)
		time.Sleep(phase.Duration)
		return
	}

	workers := phase.Attack.Workers
	if workers <= 0 {
		workers = 1
	}

	ctx := make(chan struct{})
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			workerLoop(ctx, phase.Attack, smtpAddr)
		}(w)
	}

	time.Sleep(phase.Duration)
	close(ctx)
	wg.Wait()
}

// workerLoop выполняет атаку в цикле до закрытия ctx.
func workerLoop(ctx <-chan struct{}, cfg AttackConfig, smtpAddr string) {
	var limiter <-chan time.Time
	if cfg.RatePerSec > 0 {
		// Делим общий rate на число воркеров внутри самого воркера не нужно —
		// вызывающий код уже создал N воркеров, каждый делает 1 итерацию.
		// Но rate указан суммарный, поэтому интервал = 1/rate * workers.
		// Здесь мы не знаем workers, поэтому rate передаётся как "на воркер".
		// Для удобства: rate_per_sec в YAML — суммарный, делим на workers при запуске.
		interval := time.Duration(float64(time.Second) / cfg.RatePerSec)
		t := time.NewTicker(interval)
		defer t.Stop()
		limiter = t.C
	}

	for {
		select {
		case <-ctx:
			return
		default:
		}

		if limiter != nil {
			select {
			case <-ctx:
				return
			case <-limiter:
			}
		}

		runAttack(cfg, smtpAddr)
	}
}
