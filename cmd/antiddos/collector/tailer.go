package collector

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"time"
)

// LogTailer следит за mail.log и передаёт распознанные события в буфер.
// Обрабатывает ротацию лога (файл стал короче → открыть заново).
type LogTailer struct {
	path string
	buf  *EventBuffer
}

// NewLogTailer создаёт tailer для указанного файла лога.
func NewLogTailer(path string, buf *EventBuffer) *LogTailer {
	return &LogTailer{path: path, buf: buf}
}

// Run запускает тейлинг лога. Блокирует до отмены ctx.
func (t *LogTailer) Run(ctx context.Context) {
	file := t.openWait(ctx)
	if file == nil {
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	partial := ""

	for {
		line, err := reader.ReadString('\n')
		partial += line

		if err == nil {
			if e, ok := ParseLine(partial); ok {
				t.buf.Add(e)
			}
			partial = ""
			continue
		}

		if err != io.EOF {
			log.Printf("collector/tailer: read error: %v, reopening", err)
			partial = ""
			file.Close()
			file = t.openWait(ctx)
			if file == nil {
				return
			}
			reader = bufio.NewReader(file)
			continue
		}

		// EOF: проверяем ротацию лога
		if t.rotated(file) {
			log.Printf("collector/tailer: rotation detected, reopening %s", t.path)
			partial = ""
			file.Close()
			file = t.openWait(ctx)
			if file == nil {
				return
			}
			reader = bufio.NewReader(file)
			continue
		}

		// Ждём новых строк; проверяем отмену ctx.
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// openWait открывает файл лога, ожидая его появления.
// Возвращает nil если ctx отменён.
func (t *LogTailer) openWait(ctx context.Context) *os.File {
	for {
		f, err := os.Open(t.path)
		if err == nil {
			// Стартуем с конца: не читаем историю до запуска сервиса.
			f.Seek(0, io.SeekEnd)
			log.Printf("collector/tailer: tailing %s", t.path)
			return f
		}
		log.Printf("collector/tailer: waiting for %s: %v", t.path, err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

// rotated возвращает true если файл на диске стал короче текущей позиции.
func (t *LogTailer) rotated(f *os.File) bool {
	info, err := os.Stat(t.path)
	if err != nil {
		return false
	}
	cur, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return false
	}
	return info.Size() < cur
}
