package collector

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"time"
)

type LogTailer struct {
	path string
	buf  *EventBuffer
}

func NewLogTailer(path string, buf *EventBuffer) *LogTailer {
	return &LogTailer{path: path, buf: buf}
}

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

		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (t *LogTailer) openWait(ctx context.Context) *os.File {
	for {
		f, err := os.Open(t.path)
		if err == nil {
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
