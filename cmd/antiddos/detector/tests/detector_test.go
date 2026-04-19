package detector_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
	"github.com/nnv-nick/antiddos/cmd/antiddos/detector"
)

// testThresholds возвращает пороги с простыми числами для предсказуемых тестов.
func testThresholds() detector.Thresholds {
	return detector.Thresholds{
		ConnectionFlood: detector.ConnectionFloodThresholds{
			ConnRateWarn: 10.0,
			ConnRateCrit: 30.0,
			ConnRateLow:  5.0,
		},
		JunkSession: detector.JunkSessionThresholds{
			WastedCmdRateWarn: 5.0,
			WastedCmdRateCrit: 15.0,
			WastedCmdRateLow:  2.0,
		},
		SlowLoris: detector.SlowLorisThresholds{
			ActiveSessionsWarn: 20,
			ActiveSessionsCrit: 50,
			ActiveSessionsLow:  10,
			TimeoutRateTrigger: 1.0,
			TimeoutRateLow:     0.5,
		},
		DictAttack: detector.DictAttackThresholds{
			NoqueueRateWarn: 5.0,
			NoqueueRateCrit: 15.0,
			NoqueueRateLow:  2.0,
			ConnRateMax:     10.0,
		},
	}
}

func snap() collector.Snapshot {
	return collector.Snapshot{At: time.Now()}
}

// --- ConnectionFlood ---

func TestConnFlood_Normal(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.ConnRate = 2.0
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackNone {
		t.Errorf("want AttackNone, got %v", dec.Attack)
	}
}

func TestConnFlood_Warning(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.ConnRate = 15.0
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackConnectionFlood {
		t.Errorf("want AttackConnectionFlood, got %v", dec.Attack)
	}
	if dec.Severity != detector.SeverityWarning {
		t.Errorf("want SeverityWarning, got %v", dec.Severity)
	}
}

func TestConnFlood_Critical(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.ConnRate = 50.0
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackConnectionFlood {
		t.Errorf("want AttackConnectionFlood, got %v", dec.Attack)
	}
	if dec.Severity != detector.SeverityCritical {
		t.Errorf("want SeverityCritical, got %v", dec.Severity)
	}
}

// TestConnFlood_HysteresisNoEarlyRecover проверяет, что между Warn и Low атака не гасится.
// ConnRate падает с Critical (50) до 7 — выше Low (5), значит Warning, не Normal.
func TestConnFlood_HysteresisNoEarlyRecover(t *testing.T) {
	d := detector.New(testThresholds())

	s := snap()
	s.ConnRate = 50.0
	d.Analyze(s) // → Critical

	s.ConnRate = 7.0
	dec := d.Analyze(s) // выше Low=5, должен остаться Warning, не Normal
	if dec.Attack != detector.AttackConnectionFlood {
		t.Errorf("want AttackConnectionFlood, got %v", dec.Attack)
	}
	if dec.Severity != detector.SeverityWarning {
		t.Errorf("want SeverityWarning (hysteresis), got %v", dec.Severity)
	}
}

// TestConnFlood_HysteresisRecovery проверяет, что при падении ниже Low атака гасится.
func TestConnFlood_HysteresisRecovery(t *testing.T) {
	d := detector.New(testThresholds())

	s := snap()
	s.ConnRate = 50.0
	d.Analyze(s) // → Critical

	s.ConnRate = 3.0 // ниже Low=5
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackNone {
		t.Errorf("want AttackNone after recovery, got %v / %v", dec.Attack, dec.Severity)
	}
}

// --- JunkSession ---

func TestJunkSession_Warning(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.WastedCmdRate = 8.0
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackJunkSession || dec.Severity != detector.SeverityWarning {
		t.Errorf("want JunkSession/Warning, got %v/%v", dec.Attack, dec.Severity)
	}
}

func TestJunkSession_Critical(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.WastedCmdRate = 20.0
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackJunkSession || dec.Severity != detector.SeverityCritical {
		t.Errorf("want JunkSession/Critical, got %v/%v", dec.Attack, dec.Severity)
	}
}

func TestJunkSession_HysteresisNoEarlyRecover(t *testing.T) {
	d := detector.New(testThresholds())

	s := snap()
	s.WastedCmdRate = 20.0
	d.Analyze(s) // → Critical

	s.WastedCmdRate = 3.0 // выше Low=2, ниже Warn=5
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackJunkSession {
		t.Errorf("want JunkSession (hysteresis), got %v", dec.Attack)
	}
}

func TestJunkSession_Recovery(t *testing.T) {
	d := detector.New(testThresholds())

	s := snap()
	s.WastedCmdRate = 20.0
	d.Analyze(s)

	s.WastedCmdRate = 1.0 // ниже Low=2
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackNone {
		t.Errorf("want AttackNone after recovery, got %v", dec.Attack)
	}
}

// --- SlowLoris ---

func TestSlowLoris_NeedsBothConditions(t *testing.T) {
	d := detector.New(testThresholds())

	// Только ActiveSessions — недостаточно
	s := snap()
	s.ActiveSessions = 60
	s.TimeoutRate = 0.0
	dec := d.Analyze(s)
	if dec.Attack == detector.AttackSlowLoris {
		t.Error("want no SlowLoris: TimeoutRate too low")
	}

	// Только TimeoutRate — недостаточно
	d = detector.New(testThresholds())
	s.ActiveSessions = 0
	s.TimeoutRate = 5.0
	dec = d.Analyze(s)
	if dec.Attack == detector.AttackSlowLoris {
		t.Error("want no SlowLoris: ActiveSessions too low")
	}
}

func TestSlowLoris_Warning(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.ActiveSessions = 30  // >= warn=20, < crit=50
	s.TimeoutRate = 2.0    // >= trigger=1.0
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackSlowLoris || dec.Severity != detector.SeverityWarning {
		t.Errorf("want SlowLoris/Warning, got %v/%v", dec.Attack, dec.Severity)
	}
}

func TestSlowLoris_Critical(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.ActiveSessions = 60
	s.TimeoutRate = 3.0
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackSlowLoris || dec.Severity != detector.SeverityCritical {
		t.Errorf("want SlowLoris/Critical, got %v/%v", dec.Attack, dec.Severity)
	}
}

// TestSlowLoris_RecoveryByEitherMetric проверяет, что восстановление происходит,
// если хотя бы одна метрика падает ниже low-порога.
func TestSlowLoris_RecoveryByEitherMetric(t *testing.T) {
	// Восстановление через ActiveSessions
	d := detector.New(testThresholds())
	s := snap()
	s.ActiveSessions = 60
	s.TimeoutRate = 3.0
	d.Analyze(s) // → Critical

	s.ActiveSessions = 5 // ниже low=10
	s.TimeoutRate = 3.0
	dec := d.Analyze(s)
	if dec.Attack == detector.AttackSlowLoris {
		t.Errorf("want recovery by ActiveSessions drop, got %v/%v", dec.Attack, dec.Severity)
	}

	// Восстановление через TimeoutRate
	d = detector.New(testThresholds())
	s.ActiveSessions = 60
	s.TimeoutRate = 3.0
	d.Analyze(s) // → Critical

	s.ActiveSessions = 60
	s.TimeoutRate = 0.2 // ниже low=0.5
	dec = d.Analyze(s)
	if dec.Attack == detector.AttackSlowLoris {
		t.Errorf("want recovery by TimeoutRate drop, got %v/%v", dec.Attack, dec.Severity)
	}
}

// --- DictAttack ---

func TestDictAttack_Warning(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.NoqueueRate = 8.0
	s.ConnRate = 2.0 // ниже max=10
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackDictAttack || dec.Severity != detector.SeverityWarning {
		t.Errorf("want DictAttack/Warning, got %v/%v", dec.Attack, dec.Severity)
	}
}

func TestDictAttack_Critical(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.NoqueueRate = 20.0
	s.ConnRate = 2.0
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackDictAttack || dec.Severity != detector.SeverityCritical {
		t.Errorf("want DictAttack/Critical, got %v/%v", dec.Attack, dec.Severity)
	}
}

// TestDictAttack_SuppressedByHighConnRate проверяет, что при высоком ConnRate
// атака классифицируется как connection_flood, а не dict_attack.
func TestDictAttack_SuppressedByHighConnRate(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.NoqueueRate = 20.0
	s.ConnRate = 15.0 // выше max=10 → это connection_flood
	dec := d.Analyze(s)
	if dec.Attack == detector.AttackDictAttack {
		t.Error("want no DictAttack when ConnRate is high")
	}
}

func TestDictAttack_Recovery(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.NoqueueRate = 20.0
	s.ConnRate = 2.0
	d.Analyze(s)

	s.NoqueueRate = 1.0 // ниже low=2
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackNone {
		t.Errorf("want AttackNone after recovery, got %v", dec.Attack)
	}
}

// --- Приоритет ---

// TestPriority_ConnFloodBeatsDict проверяет, что ConnectionFlood имеет приоритет над DictAttack.
func TestPriority_ConnFloodBeatsDict(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.ConnRate = 50.0    // → ConnectionFlood/Critical
	s.NoqueueRate = 20.0 // → DictAttack (но ConnRate > max, поэтому не сработает)
	// Но даже если оба сработают — ConnFlood имеет приоритет
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackConnectionFlood {
		t.Errorf("want AttackConnectionFlood (priority), got %v", dec.Attack)
	}
}

// TestPriority_ConnFloodBeatsJunk проверяет, что ConnectionFlood имеет приоритет над JunkSession.
func TestPriority_ConnFloodBeatsJunk(t *testing.T) {
	d := detector.New(testThresholds())
	s := snap()
	s.ConnRate = 50.0
	s.WastedCmdRate = 20.0
	dec := d.Analyze(s)
	if dec.Attack != detector.AttackConnectionFlood {
		t.Errorf("want AttackConnectionFlood (priority over JunkSession), got %v", dec.Attack)
	}
}

// --- Thresholds: LoadFromFile ---

func TestLoadFromFile_Valid(t *testing.T) {
	yaml := `
connection_flood:
  conn_rate_warn: 100.0
  conn_rate_crit: 200.0
  conn_rate_low: 50.0
`
	f, err := os.CreateTemp(t.TempDir(), "thresholds*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(yaml)
	f.Close()

	th, err := detector.LoadFromFile(f.Name())
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if th.ConnectionFlood.ConnRateWarn != 100.0 {
		t.Errorf("want ConnRateWarn=100, got %v", th.ConnectionFlood.ConnRateWarn)
	}
	if th.ConnectionFlood.ConnRateCrit != 200.0 {
		t.Errorf("want ConnRateCrit=200, got %v", th.ConnectionFlood.ConnRateCrit)
	}
	// Остальные поля должны взяться из DefaultThresholds
	def := detector.DefaultThresholds()
	if th.JunkSession.WastedCmdRateWarn != def.JunkSession.WastedCmdRateWarn {
		t.Errorf("want default JunkSession.WastedCmdRateWarn=%v, got %v",
			def.JunkSession.WastedCmdRateWarn, th.JunkSession.WastedCmdRateWarn)
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := detector.LoadFromFile(filepath.Join(t.TempDir(), "nonexistent.yml"))
	if err == nil {
		t.Error("want error for missing file, got nil")
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("connection_flood:\n  conn_rate_warn: [unclosed")
	f.Close()

	_, err = detector.LoadFromFile(f.Name())
	if err == nil {
		t.Error("want error for invalid YAML, got nil")
	}
}

// --- String() методы ---

func TestAttackTypeString(t *testing.T) {
	cases := []struct {
		at   detector.AttackType
		want string
	}{
		{detector.AttackNone, "none"},
		{detector.AttackConnectionFlood, "connection_flood"},
		{detector.AttackJunkSession, "junk_session"},
		{detector.AttackSlowLoris, "slow_loris"},
		{detector.AttackDictAttack, "dict_attack"},
	}
	for _, c := range cases {
		if got := c.at.String(); got != c.want {
			t.Errorf("AttackType(%d).String() = %q, want %q", c.at, got, c.want)
		}
	}
}

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sv   detector.Severity
		want string
	}{
		{detector.SeverityNormal, "normal"},
		{detector.SeverityWarning, "warning"},
		{detector.SeverityCritical, "critical"},
	}
	for _, c := range cases {
		if got := c.sv.String(); got != c.want {
			t.Errorf("Severity(%d).String() = %q, want %q", c.sv, got, c.want)
		}
	}
}
