package actuator_test

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nnv-nick/antiddos/cmd/antiddos/actuator"
	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
	"github.com/nnv-nick/antiddos/cmd/antiddos/detector"
)

func testConfig() actuator.Config {
	return actuator.Config{
		BaselineAlpha: 1.0,
		ConnectionFlood: actuator.ConnectionFloodActConfig{
			RateLimitMultiplierWarn: 2.0,
			RateLimitMultiplierCrit: 1.0,
			RateLimitMin:            5,
		},
		SlowLoris: actuator.SlowLorisActConfig{
			TimeoutWarnSec:     120,
			TimeoutCritSec:     60,
			ConnCountLimitWarn: 5,
			ConnCountLimitCrit: 3,
		},
		JunkSession: actuator.JunkSessionActConfig{
			HardErrorLimitWarn: 10,
			HardErrorLimitCrit: 5,
		},
		DictAttack: actuator.DictAttackActConfig{
			ErrorSleepDivisor: 5.0,
			ErrorSleepMinSec:  1,
			ErrorSleepMaxSec:  10,
		},
	}
}

func snap() collector.Snapshot {
	return collector.Snapshot{At: time.Now()}
}

func dec(attack detector.AttackType, sev detector.Severity) detector.Decision {
	return detector.Decision{Attack: attack, Severity: sev}
}

func TestBaseline_FirstValue(t *testing.T) {
	b := actuator.NewEMABaseline(0.5)
	if b.Initialized() {
		t.Fatal("want not initialized before first update")
	}
	b.Update(10.0)
	if !b.Initialized() {
		t.Fatal("want initialized after first update")
	}
	if b.ConnRate != 10.0 {
		t.Errorf("want ConnRate=10.0 after first update, got %.2f", b.ConnRate)
	}
}

func TestBaseline_EMA(t *testing.T) {
	b := actuator.NewEMABaseline(0.5)
	b.Update(10.0)
	b.Update(20.0)
	want := 15.0
	if math.Abs(b.ConnRate-want) > 1e-9 {
		t.Errorf("want ConnRate=%.2f, got %.2f", want, b.ConnRate)
	}
}

func TestBaseline_MultipleUpdates(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	b.Update(5.0)
	b.Update(7.0)
	b.Update(3.0)
	if b.ConnRate != 3.0 {
		t.Errorf("want ConnRate=3.0 with α=1, got %.2f", b.ConnRate)
	}
}

func TestComputeLines_Normal_ReturnsDefaults(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	b.Update(2.0)
	lines := actuator.ComputeLines(dec(detector.AttackNone, detector.SeverityNormal), snap(), b, testConfig())
	want := []string{
		"smtpd_client_connection_rate_limit = 0",
		"smtpd_hard_error_limit = 20",
		"smtpd_error_sleep_time = 1s",
		"smtpd_timeout = 300s",
		"smtpd_per_record_deadline = no",
		"smtpd_client_connection_count_limit = 50",
	}
	if !equalLines(lines, want) {
		t.Errorf("want default lines:\n%v\ngot:\n%v", want, lines)
	}
}

func TestComputeLines_ConnFlood_Warning(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	b.Update(2.0)

	lines := actuator.ComputeLines(dec(detector.AttackConnectionFlood, detector.SeverityWarning), snap(), b, testConfig())
	want := "smtpd_client_connection_rate_limit = 240"
	if len(lines) != 1 || lines[0] != want {
		t.Errorf("want %q, got %v", want, lines)
	}
}

func TestComputeLines_ConnFlood_Critical(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	b.Update(2.0)

	lines := actuator.ComputeLines(dec(detector.AttackConnectionFlood, detector.SeverityCritical), snap(), b, testConfig())
	want := "smtpd_client_connection_rate_limit = 120"
	if len(lines) != 1 || lines[0] != want {
		t.Errorf("want %q, got %v", want, lines)
	}
}

func TestComputeLines_ConnFlood_MinClamp(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	b.Update(0.01)

	lines := actuator.ComputeLines(dec(detector.AttackConnectionFlood, detector.SeverityWarning), snap(), b, testConfig())
	want := "smtpd_client_connection_rate_limit = 5"
	if len(lines) != 1 || lines[0] != want {
		t.Errorf("want %q (min clamp), got %v", want, lines)
	}
}

func TestComputeLines_SlowLoris_Warning(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	lines := actuator.ComputeLines(dec(detector.AttackSlowLoris, detector.SeverityWarning), snap(), b, testConfig())
	want := []string{
		"smtpd_per_record_deadline = yes",
		"smtpd_timeout = 120s",
		"smtpd_client_connection_count_limit = 5",
	}
	if !equalLines(lines, want) {
		t.Errorf("want %v, got %v", want, lines)
	}
}

func TestComputeLines_SlowLoris_Critical(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	lines := actuator.ComputeLines(dec(detector.AttackSlowLoris, detector.SeverityCritical), snap(), b, testConfig())
	want := []string{
		"smtpd_per_record_deadline = yes",
		"smtpd_timeout = 60s",
		"smtpd_client_connection_count_limit = 3",
	}
	if !equalLines(lines, want) {
		t.Errorf("want %v, got %v", want, lines)
	}
}

func TestComputeLines_JunkSession_Warning(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	lines := actuator.ComputeLines(dec(detector.AttackJunkSession, detector.SeverityWarning), snap(), b, testConfig())
	want := "smtpd_hard_error_limit = 10"
	if len(lines) != 1 || lines[0] != want {
		t.Errorf("want %q, got %v", want, lines)
	}
}

func TestComputeLines_JunkSession_Critical(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	lines := actuator.ComputeLines(dec(detector.AttackJunkSession, detector.SeverityCritical), snap(), b, testConfig())
	want := "smtpd_hard_error_limit = 5"
	if len(lines) != 1 || lines[0] != want {
		t.Errorf("want %q, got %v", want, lines)
	}
}

func TestComputeLines_DictAttack_Proportional(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	s := snap()
	s.NoqueueRate = 20.0

	lines := actuator.ComputeLines(dec(detector.AttackDictAttack, detector.SeverityWarning), s, b, testConfig())
	want := "smtpd_error_sleep_time = 4s"
	if len(lines) != 1 || lines[0] != want {
		t.Errorf("want %q, got %v", want, lines)
	}
}

func TestComputeLines_DictAttack_MaxClamp(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	s := snap()
	s.NoqueueRate = 100.0

	lines := actuator.ComputeLines(dec(detector.AttackDictAttack, detector.SeverityWarning), s, b, testConfig())
	want := "smtpd_error_sleep_time = 10s"
	if len(lines) != 1 || lines[0] != want {
		t.Errorf("want %q (max clamp), got %v", want, lines)
	}
}

func TestComputeLines_DictAttack_MinClamp(t *testing.T) {
	b := actuator.NewEMABaseline(1.0)
	s := snap()
	s.NoqueueRate = 0.1

	lines := actuator.ComputeLines(dec(detector.AttackDictAttack, detector.SeverityWarning), s, b, testConfig())
	want := "smtpd_error_sleep_time = 1s"
	if len(lines) != 1 || lines[0] != want {
		t.Errorf("want %q (min clamp), got %v", want, lines)
	}
}

func newActuatorInTempDir(t *testing.T) (*actuator.Actuator, string) {
	t.Helper()
	dir := t.TempDir()
	a := actuator.New(dir, testConfig())
	return a, dir
}

func TestActuator_Apply_WritesFiles(t *testing.T) {
	a, dir := newActuatorInTempDir(t)

	s := snap()
	s.ConnRate = 2.0
	if err := a.Apply(dec(detector.AttackNone, detector.SeverityNormal), s); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	cfPath := filepath.Join(dir, "antiddos.cf")
	data, err := os.ReadFile(cfPath)
	if err != nil {
		t.Fatalf("antiddos.cf not created: %v", err)
	}
	if !strings.Contains(string(data), "smtpd_client_connection_rate_limit") {
		t.Errorf("antiddos.cf missing expected content:\n%s", data)
	}

	reloadPath := filepath.Join(dir, "reload")
	if _, err := os.Stat(reloadPath); err != nil {
		t.Fatalf("reload not created: %v", err)
	}
}

func TestActuator_Apply_Idempotent(t *testing.T) {
	a, dir := newActuatorInTempDir(t)

	s := snap()
	s.ConnRate = 2.0
	d := dec(detector.AttackNone, detector.SeverityNormal)

	if err := a.Apply(d, s); err != nil {
		t.Fatal(err)
	}

	reloadPath := filepath.Join(dir, "reload")
	os.Remove(reloadPath)

	if err := a.Apply(d, s); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(reloadPath); err == nil {
		t.Error("reload should NOT be recreated on idempotent Apply")
	}
}

func TestActuator_Apply_ReappliesOnDecisionChange(t *testing.T) {
	a, dir := newActuatorInTempDir(t)

	s := snap()
	s.ConnRate = 2.0

	if err := a.Apply(dec(detector.AttackNone, detector.SeverityNormal), s); err != nil {
		t.Fatal(err)
	}

	reloadPath := filepath.Join(dir, "reload")
	os.Remove(reloadPath)

	if err := a.Apply(dec(detector.AttackConnectionFlood, detector.SeverityWarning), s); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(reloadPath); err != nil {
		t.Error("reload should be created after decision change")
	}

	cfPath := filepath.Join(dir, "antiddos.cf")
	data, err := os.ReadFile(cfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "smtpd_client_connection_rate_limit = 240") {
		t.Errorf("want connection rate limit in config, got:\n%s", data)
	}
}

func TestActuator_Apply_BaselineUpdatedOnNormal(t *testing.T) {
	a, _ := newActuatorInTempDir(t)

	s := snap()
	s.ConnRate = 5.0
	a.Apply(dec(detector.AttackNone, detector.SeverityNormal), s) //nolint

	s2 := snap()
	s2.ConnRate = 5.0

	a2, dir2 := newActuatorInTempDir(t)
	sBase := snap()
	sBase.ConnRate = 5.0
	a2.Apply(dec(detector.AttackNone, detector.SeverityNormal), sBase) //nolint

	if err := a2.Apply(dec(detector.AttackConnectionFlood, detector.SeverityWarning), s2); err != nil {
		t.Fatal(err)
	}

	cfPath := filepath.Join(dir2, "antiddos.cf")
	data, _ := os.ReadFile(cfPath)
	if !strings.Contains(string(data), "smtpd_client_connection_rate_limit = 600") {
		t.Errorf("want limit=600 (baseline=5/s), got:\n%s", data)
	}
}

func TestActuator_Apply_BaselineNotUpdatedDuringAttack(t *testing.T) {
	a, dir := newActuatorInTempDir(t)

	sNormal := snap()
	sNormal.ConnRate = 2.0
	a.Apply(dec(detector.AttackNone, detector.SeverityNormal), sNormal) //nolint

	sAttack := snap()
	sAttack.ConnRate = 500.0
	a.Apply(dec(detector.AttackConnectionFlood, detector.SeverityWarning), sAttack) //nolint

	sRecovered := snap()
	sRecovered.ConnRate = 2.0
	a.Apply(dec(detector.AttackNone, detector.SeverityNormal), sRecovered) //nolint

	os.Remove(filepath.Join(dir, "reload"))

	sAttack2 := snap()
	sAttack2.ConnRate = 500.0
	a.Apply(dec(detector.AttackConnectionFlood, detector.SeverityWarning), sAttack2) //nolint

	data, _ := os.ReadFile(filepath.Join(dir, "antiddos.cf"))
	if !strings.Contains(string(data), "smtpd_client_connection_rate_limit = 240") {
		t.Errorf("baseline should not be updated during attack, got:\n%s", data)
	}
}

func TestLoadConfigFromFile_Valid(t *testing.T) {
	yaml := `
actuator:
  baseline_alpha: 0.2
  connection_flood:
    rate_limit_multiplier_warn: 3.0
    rate_limit_multiplier_crit: 1.5
    rate_limit_min: 10
`
	f, err := os.CreateTemp(t.TempDir(), "*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(yaml)
	f.Close()

	cfg, err := actuator.LoadConfigFromFile(f.Name())
	if err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	if cfg.BaselineAlpha != 0.2 {
		t.Errorf("want BaselineAlpha=0.2, got %v", cfg.BaselineAlpha)
	}
	if cfg.ConnectionFlood.RateLimitMultiplierWarn != 3.0 {
		t.Errorf("want RateLimitMultiplierWarn=3.0, got %v", cfg.ConnectionFlood.RateLimitMultiplierWarn)
	}
	def := actuator.DefaultConfig()
	if cfg.SlowLoris.TimeoutWarnSec != def.SlowLoris.TimeoutWarnSec {
		t.Errorf("want default TimeoutWarnSec=%d, got %d",
			def.SlowLoris.TimeoutWarnSec, cfg.SlowLoris.TimeoutWarnSec)
	}
}

func TestLoadConfigFromFile_NotFound(t *testing.T) {
	_, err := actuator.LoadConfigFromFile(filepath.Join(t.TempDir(), "nonexistent.yml"))
	if err == nil {
		t.Error("want error for missing file")
	}
}

func TestLoadConfigFromFile_IgnoresDetectorKeys(t *testing.T) {
	yaml := `
connection_flood:
  conn_rate_warn: 10.0
  conn_rate_crit: 30.0
  conn_rate_low: 5.0
actuator:
  baseline_alpha: 0.3
`
	f, err := os.CreateTemp(t.TempDir(), "*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(yaml)
	f.Close()

	cfg, err := actuator.LoadConfigFromFile(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BaselineAlpha != 0.3 {
		t.Errorf("want BaselineAlpha=0.3, got %v", cfg.BaselineAlpha)
	}
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
