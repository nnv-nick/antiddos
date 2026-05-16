package collector_test

import (
	"testing"

	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
)

const emptyQueueOutput = "Mail queue is empty\n"

const sampleQueueOutput = `
-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
3B2F41C0A2A*     488 Fri Apr 18 12:00:01  user@test.local
                                         dest@test.local

A1D2E1C0B3C      512 Fri Apr 18 12:00:02  other@test.local
                                         dest2@test.local

-- 2 Kbytes in 2 Requests.
`

const singleEntryOutput = `
4A1BC1D0E2F      256 Fri Apr 18 12:01:00  sender@example.com
                                         rcpt@example.com

-- 0 Kbytes in 1 Request.
`

func TestCountQueuedEmpty(t *testing.T) {
	n := collector.CountQueued(emptyQueueOutput)
	if n != 0 {
		t.Errorf("CountQueued(empty) = %d, want 0", n)
	}
}

func TestCountQueuedMultiple(t *testing.T) {
	n := collector.CountQueued(sampleQueueOutput)
	if n != 2 {
		t.Errorf("CountQueued(sample) = %d, want 2", n)
	}
}

func TestCountQueuedSingle(t *testing.T) {
	n := collector.CountQueued(singleEntryOutput)
	if n != 1 {
		t.Errorf("CountQueued(single) = %d, want 1", n)
	}
}

func TestCountQueuedNoHeader(t *testing.T) {
	out := "ABCDEF1234AB      100 Fri Apr 18 12:00:00  a@b.com\n"
	n := collector.CountQueued(out)
	if n != 1 {
		t.Errorf("CountQueued(minimal) = %d, want 1", n)
	}
}
