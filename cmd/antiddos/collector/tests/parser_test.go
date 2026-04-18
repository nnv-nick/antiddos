package collector_test

import (
	"testing"
	"time"

	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
)

func TestParseLineConnect(t *testing.T) {
	line := "Apr 18 12:00:01 mail postfix/smtpd[1234]: connect from unknown[172.20.0.5]"
	e, ok := collector.ParseLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if e.Type != collector.EvConnect {
		t.Errorf("type = %v, want EvConnect", e.Type)
	}
	if e.At.IsZero() {
		t.Error("At is zero")
	}
}

func TestParseLineDisconnectFull(t *testing.T) {
	// Легитимная сессия: mail=1
	line := "Apr 18 12:00:02 mail postfix/smtpd[1234]: disconnect from unknown[172.20.0.5] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5"
	e, ok := collector.ParseLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if e.Type != collector.EvDisconnect {
		t.Errorf("type = %v, want EvDisconnect", e.Type)
	}
	if e.Commands != 5 {
		t.Errorf("Commands = %d, want 5", e.Commands)
	}
	if e.Mail != 1 {
		t.Errorf("Mail = %d, want 1", e.Mail)
	}
}

func TestParseLineDisconnectJunkEhlo(t *testing.T) {
	// EHLO-спам: commands=50, mail=0
	line := "Apr 18 12:00:03 mail postfix/smtpd[1234]: disconnect from unknown[172.20.0.5] ehlo=50 commands=50"
	e, ok := collector.ParseLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if e.Commands != 50 {
		t.Errorf("Commands = %d, want 50", e.Commands)
	}
	if e.Mail != 0 {
		t.Errorf("Mail = %d, want 0", e.Mail)
	}
}

func TestParseLineDisconnectJunkUnknown(t *testing.T) {
	// XJUNK-спам: unknown=14, mail=0
	line := "Apr 18 12:00:04 mail postfix/smtpd[1234]: disconnect from unknown[172.20.0.5] ehlo=1 unknown=14 commands=15"
	e, ok := collector.ParseLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if e.Commands != 15 {
		t.Errorf("Commands = %d, want 15", e.Commands)
	}
	if e.Mail != 0 {
		t.Errorf("Mail = %d, want 0", e.Mail)
	}
}

func TestParseLineNoqueue(t *testing.T) {
	line := "Apr 18 12:00:05 mail postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 550 relay denied"
	e, ok := collector.ParseLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if e.Type != collector.EvNoqueue {
		t.Errorf("type = %v, want EvNoqueue", e.Type)
	}
}

func TestParseLineTimeout(t *testing.T) {
	line := "Apr 18 12:00:06 mail postfix/smtpd[1234]: timeout after CONNECT from unknown[1.2.3.4]"
	e, ok := collector.ParseLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if e.Type != collector.EvTimeout {
		t.Errorf("type = %v, want EvTimeout", e.Type)
	}
}

func TestParseLineNonSmtp(t *testing.T) {
	line := "Apr 18 12:00:07 mail postfix/smtpd[1234]: warning: non-SMTP command from unknown[198.51.100.11]: GET / HTTP/1.1"
	e, ok := collector.ParseLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	// non-SMTP трактуем как мусорный disconnect
	if e.Type != collector.EvDisconnect {
		t.Errorf("type = %v, want EvDisconnect", e.Type)
	}
	if e.Mail != 0 {
		t.Errorf("Mail = %d, want 0", e.Mail)
	}
	if e.Commands != 1 {
		t.Errorf("Commands = %d, want 1", e.Commands)
	}
}

func TestParseLineIrrelevant(t *testing.T) {
	lines := []string{
		"Apr 18 12:00:00 mail postfix/qmgr[99]: ABC123: from=<user@test.local>, size=512",
		"Apr 18 12:00:00 mail postfix/smtp[99]: ABC123: to=<x@test.local>, status=sent",
		"Apr 18 12:00:00 mail rsyslogd: start",
		"",
	}
	for _, l := range lines {
		_, ok := collector.ParseLine(l)
		if ok {
			t.Errorf("expected ok=false for line: %q", l)
		}
	}
}

func TestParseLineTimestamp(t *testing.T) {
	before := time.Now()
	line := "Apr 18 12:00:01 mail postfix/smtpd[1]: connect from unknown[1.2.3.4]"
	e, _ := collector.ParseLine(line)
	after := time.Now()
	if e.At.Before(before) || e.At.After(after) {
		t.Errorf("At = %v, want between %v and %v", e.At, before, after)
	}
}
