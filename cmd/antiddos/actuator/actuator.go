package actuator

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
	"github.com/nnv-nick/antiddos/cmd/antiddos/detector"
)

type Actuator struct {
	ctlDir       string
	cfg          Config
	baseline     *EMABaseline
	lastDecision detector.Decision
	lastLines    []string
}

func New(ctlDir string, cfg Config) *Actuator {
	return &Actuator{
		ctlDir:   ctlDir,
		cfg:      cfg,
		baseline: NewEMABaseline(cfg.BaselineAlpha),
	}
}

func (a *Actuator) Apply(dec detector.Decision, snap collector.Snapshot) error {
	if dec.Attack == detector.AttackNone {
		a.baseline.Update(snap.ConnRate)
	}

	lines := ComputeLines(dec, snap, a.baseline, a.cfg)

	if dec == a.lastDecision && equalLines(lines, a.lastLines) {
		return nil
	}

	if err := a.writeConfig(lines); err != nil {
		return fmt.Errorf("actuator: write config: %w", err)
	}
	if err := a.triggerReload(); err != nil {
		return fmt.Errorf("actuator: trigger reload: %w", err)
	}

	log.Printf("actuator: applied attack=%s severity=%s config=%v",
		dec.Attack, dec.Severity, lines)

	a.lastDecision = dec
	a.lastLines = lines
	return nil
}

func (a *Actuator) writeConfig(lines []string) error {
	content := strings.Join(lines, "\n") + "\n"
	path := filepath.Join(a.ctlDir, "antiddos.cf")
	return os.WriteFile(path, []byte(content), 0644)
}

func (a *Actuator) triggerReload() error {
	path := filepath.Join(a.ctlDir, "reload")
	return os.WriteFile(path, []byte{}, 0644)
}

func equalLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
