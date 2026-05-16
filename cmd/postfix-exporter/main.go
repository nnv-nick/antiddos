package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	reConnect    = regexp.MustCompile(`postfix/smtpd\[\d+\]: connect from `)
	reDisconnect = regexp.MustCompile(`postfix/smtpd\[\d+\]: disconnect from `)
	reNoqueue    = regexp.MustCompile(`postfix/smtpd\[\d+\]: NOQUEUE: reject`)
	reReject     = regexp.MustCompile(`postfix/smtpd\[\d+\]: [A-F0-9]+: reject`)
	reStatusSent = regexp.MustCompile(`postfix/smtp\[\d+\]:.*status=sent`)
	reStatusDef  = regexp.MustCompile(`postfix/smtp\[\d+\]:.*status=deferred`)
	reStatusBnc  = regexp.MustCompile(`postfix/smtp\[\d+\]:.*status=bounced`)
	reQueued     = regexp.MustCompile(`postfix/qmgr\[\d+\]:.*from=<`)
	reRemoved    = regexp.MustCompile(`postfix/qmgr\[\d+\]:.*removed`)
	reExpired    = regexp.MustCompile(`postfix/qmgr\[\d+\]:.*expired`)
)

var (
	metConnects = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_smtpd_connects_total",
		Help: "Total SMTP connections accepted",
	})
	metDisconnects = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_smtpd_disconnects_total",
		Help: "Total SMTP disconnections",
	})
	metRejectsNoqueue = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_smtpd_noqueue_rejects_total",
		Help: "Connections rejected before queue (NOQUEUE)",
	})
	metRejects = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_smtpd_rejects_total",
		Help: "Messages rejected after DATA",
	})
	metDelivered = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_smtp_delivered_total",
		Help: "Messages successfully delivered (status=sent)",
	})
	metDeferred = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_smtp_deferred_total",
		Help: "Messages deferred",
	})
	metBounced = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_smtp_bounced_total",
		Help: "Messages bounced",
	})
	metQueued = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_qmgr_queued_total",
		Help: "Messages added to queue",
	})
	metRemoved = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_qmgr_removed_total",
		Help: "Messages removed from queue (delivered or bounced)",
	})
	metExpired = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_qmgr_expired_total",
		Help: "Messages expired from queue",
	})
	metQueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "postfix_queue_depth",
		Help: "Current number of messages in the queue (queued - removed - expired)",
	})
	metLines = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "postfix_exporter_lines_total",
		Help: "Total log lines processed",
	})
)

func init() {
	prometheus.MustRegister(
		metConnects, metDisconnects,
		metRejectsNoqueue, metRejects,
		metDelivered, metDeferred, metBounced,
		metQueued, metRemoved, metExpired,
		metQueueDepth,
		metLines,
	)
}

func processLine(line string) {
	metLines.Inc()
	switch {
	case reConnect.MatchString(line):
		metConnects.Inc()
	case reDisconnect.MatchString(line):
		metDisconnects.Inc()
	case reNoqueue.MatchString(line):
		metRejectsNoqueue.Inc()
	case reReject.MatchString(line):
		metRejects.Inc()
	case reStatusSent.MatchString(line):
		metDelivered.Inc()
	case reStatusDef.MatchString(line):
		metDeferred.Inc()
	case reStatusBnc.MatchString(line):
		metBounced.Inc()
	case reQueued.MatchString(line):
		metQueued.Inc()
		metQueueDepth.Inc()
	case reRemoved.MatchString(line):
		metRemoved.Inc()
		metQueueDepth.Dec()
	case reExpired.MatchString(line):
		metExpired.Inc()
		metQueueDepth.Dec()
	}
}

func tailLog(path string) {
	var (
		file   *os.File
		reader *bufio.Reader
		offset int64
		err    error
	)

	openFile := func() {
		if file != nil {
			file.Close()
		}
		for {
			file, err = os.Open(path)
			if err != nil {
				log.Printf("waiting for log file %s: %v", path, err)
				time.Sleep(2 * time.Second)
				continue
			}
			offset, _ = file.Seek(0, io.SeekEnd)
			reader = bufio.NewReader(file)
			log.Printf("tailing %s from offset %d", path, offset)
			return
		}
	}

	openFile()

	buf := ""
	for {
		line, err := reader.ReadString('\n')
		buf += line

		if err == nil {
			processLine(buf)
			buf = ""
			continue
		}

		if err == io.EOF {
			info, statErr := os.Stat(path)
			if statErr == nil {
				cur, _ := file.Seek(0, io.SeekCurrent)
				if info.Size() < cur {
					log.Printf("log rotation detected, reopening %s", path)
					buf = ""
					openFile()
					continue
				}
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}

		log.Printf("read error: %v, reopening", err)
		buf = ""
		openFile()
	}
}

func main() {
	logPath := flag.String("postfix.logfile_path", "/var/log/mail.log", "Path to Postfix mail.log")
	listenAddr := flag.String("web.listen-address", ":9154", "Prometheus metrics listen address")
	flag.Parse()

	log.Printf("postfix-exporter: log=%s metrics=%s", *logPath, *listenAddr)

	go tailLog(*logPath)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<a href="/metrics">metrics</a>`))
	})
	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		log.Fatalf("metrics server: %v", err)
	}
}
