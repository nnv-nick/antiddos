package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

func runAttack(cfg AttackConfig, smtpAddr string) {
	switch cfg.Type {
	case "connection_flood":
		attackConnectionFlood(cfg, smtpAddr)
	case "junk_session":
		attackJunkSession(cfg, smtpAddr)
	case "rcpt_dictionary":
		attackRcptDictionary(cfg, smtpAddr)
	case "slow_loris":
		attackSlowLoris(cfg, smtpAddr)
	case "sender_rotation":
		attackSenderRotation(cfg, smtpAddr)
	case "no_attack":
		time.Sleep(100 * time.Millisecond)
	default:
		time.Sleep(100 * time.Millisecond)
	}
}

func attackConnectionFlood(cfg AttackConfig, addr string) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	metricsAttackConnections.Inc()
	if err != nil {
		return
	}
	defer conn.Close()
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	conn.Read(buf)
}

func attackJunkSession(cfg AttackConfig, addr string) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	metricsAttackConnections.Inc()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 512)
	conn.Read(buf)

	n := cfg.JunkCommandsPerSession
	if n == 0 {
		n = 50
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(conn, "XJUNK%d\r\n", i)
		conn.Read(buf)
		metricsAttackMessages.Inc()
	}
	fmt.Fprintf(conn, "QUIT\r\n")
}

func attackRcptDictionary(cfg AttackConfig, addr string) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	metricsAttackConnections.Inc()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	buf := make([]byte, 512)
	conn.Read(buf)

	from := pickSender(cfg)
	fmt.Fprintf(conn, "EHLO attacker.test\r\n")
	conn.Read(buf)
	fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", from)
	conn.Read(buf)

	n := cfg.RcptPerSession
	if n == 0 {
		n = 100
	}
	for i := 0; i < n; i++ {
		user := fmt.Sprintf("user%d", rand.Intn(100000))
		fmt.Fprintf(conn, "RCPT TO:<%s@test.local>\r\n", user)
		conn.Read(buf)
		metricsAttackMessages.Inc()
	}
	fmt.Fprintf(conn, "QUIT\r\n")
}

func attackSlowLoris(cfg AttackConfig, addr string) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	metricsAttackConnections.Inc()
	if err != nil {
		return
	}
	defer conn.Close()

	delayMs := cfg.SlowLorisDelayMs
	if delayMs == 0 {
		delayMs = 5000
	}
	delay := time.Duration(delayMs) * time.Millisecond

	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.Read(buf)

	cmd := "EHLO slow.attacker.test\r\n"
	conn.SetWriteDeadline(time.Time{})
	for _, b := range []byte(cmd) {
		conn.Write([]byte{b})
		time.Sleep(delay)
	}
}

func attackSenderRotation(cfg AttackConfig, addr string) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	metricsAttackConnections.Inc()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 512)
	conn.Read(buf)

	from := pickSender(cfg)
	ehloHost := randomSubdomain()

	fmt.Fprintf(conn, "EHLO %s\r\n", ehloHost)
	conn.Read(buf)
	fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", from)
	conn.Read(buf)
	fmt.Fprintf(conn, "RCPT TO:<victim@test.local>\r\n")
	conn.Read(buf)
	fmt.Fprintf(conn, "DATA\r\n")
	conn.Read(buf)
	fmt.Fprintf(conn, "Subject: spam\r\n\r\nspam body\r\n.\r\n")
	conn.Read(buf)
	fmt.Fprintf(conn, "QUIT\r\n")
	metricsAttackMessages.Inc()
}

func pickSender(cfg AttackConfig) string {
	domains := cfg.SenderDomains
	if len(domains) == 0 {
		domains = []string{"evil.test", "spam.example", "attack.local"}
	}
	domain := domains[rand.Intn(len(domains))]
	user := fmt.Sprintf("user%d", rand.Intn(10000))
	return fmt.Sprintf("%s@%s", user, domain)
}

func randomSubdomain() string {
	parts := []string{"mail", "mx", "smtp", "relay", "out"}
	tlds := []string{"test", "example", "local", "invalid"}
	return fmt.Sprintf("%s%d.%s.%s",
		parts[rand.Intn(len(parts))],
		rand.Intn(999),
		strings.Repeat("x", rand.Intn(5)+3),
		tlds[rand.Intn(len(tlds))],
	)
}
