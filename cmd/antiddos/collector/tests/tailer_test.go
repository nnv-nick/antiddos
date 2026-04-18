package collector_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
)

// TestTailerReadsNewLines проверяет, что tailer подхватывает строки,
// дописанные в файл после его открытия.
func TestTailerReadsNewLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.log")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	buf := collector.NewEventBuffer(30 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go collector.NewLogTailer(path, buf).Run(ctx)

	// Даём tailer'у время открыть файл и встать на EOF
	time.Sleep(100 * time.Millisecond)

	line := "Apr 18 12:00:01 mail postfix/smtpd[1]: connect from unknown[1.2.3.4]\n"
	f.WriteString(line)
	f.Sync()
	f.Close()

	// Ждём обработки (poll-интервал = 200ms)
	time.Sleep(500 * time.Millisecond)

	s := buf.Snapshot()
	if s.ConnRate == 0 {
		t.Error("expected ConnRate > 0 after writing connect line")
	}
}

// TestTailerIgnoresExistingContent проверяет, что строки до запуска не читаются.
func TestTailerIgnoresExistingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.log")

	existingLine := "Apr 18 11:00:00 mail postfix/smtpd[1]: connect from unknown[1.2.3.4]\n"
	if err := os.WriteFile(path, []byte(existingLine), 0644); err != nil {
		t.Fatal(err)
	}

	buf := collector.NewEventBuffer(30 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go collector.NewLogTailer(path, buf).Run(ctx)

	time.Sleep(400 * time.Millisecond)

	s := buf.Snapshot()
	if s.ConnRate != 0 {
		t.Errorf("ConnRate = %.4f, want 0 (pre-existing lines should be skipped)", s.ConnRate)
	}
}

// TestTailerCancelStops проверяет, что Run завершается при отмене ctx.
func TestTailerCancelStops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.log")
	os.WriteFile(path, nil, 0644)

	buf := collector.NewEventBuffer(30 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		collector.NewLogTailer(path, buf).Run(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run did not stop after ctx cancellation")
	}
}

// TestTailerMultipleEvents проверяет обработку нескольких строк разных типов.
func TestTailerMultipleEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.log")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	buf := collector.NewEventBuffer(30 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go collector.NewLogTailer(path, buf).Run(ctx)
	time.Sleep(100 * time.Millisecond)

	lines := []string{
		"Apr 18 12:00:01 mail postfix/smtpd[1]: connect from unknown[1.2.3.4]\n",
		"Apr 18 12:00:02 mail postfix/smtpd[1]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 550\n",
		"Apr 18 12:00:03 mail postfix/smtpd[1]: disconnect from unknown[1.2.3.4] ehlo=1 unknown=14 commands=15\n",
	}
	for _, l := range lines {
		f.WriteString(l)
	}
	f.Sync()
	f.Close()

	time.Sleep(500 * time.Millisecond)

	s := buf.Snapshot()
	if s.ConnRate == 0 {
		t.Error("expected ConnRate > 0")
	}
	if s.NoqueueRate == 0 {
		t.Error("expected NoqueueRate > 0")
	}
	if s.WastedCmdRate == 0 {
		t.Error("expected WastedCmdRate > 0 (disconnect with mail=0, commands=15)")
	}
}
