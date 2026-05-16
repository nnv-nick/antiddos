package detector

import (
	"sync"

	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
)

type AttackType int

const (
	AttackNone           AttackType = iota
	AttackConnectionFlood
	AttackJunkSession
	AttackSlowLoris
	AttackDictAttack

	attackTypeCount
)

func (a AttackType) String() string {
	switch a {
	case AttackConnectionFlood:
		return "connection_flood"
	case AttackJunkSession:
		return "junk_session"
	case AttackSlowLoris:
		return "slow_loris"
	case AttackDictAttack:
		return "dict_attack"
	default:
		return "none"
	}
}

type Severity int

const (
	SeverityNormal   Severity = iota
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	default:
		return "normal"
	}
}

type Decision struct {
	Attack   AttackType
	Severity Severity
}

type Detector struct {
	t      Thresholds
	mu     sync.Mutex
	states [attackTypeCount]Severity
}

func New(t Thresholds) *Detector {
	return &Detector{t: t}
}

func (d *Detector) Analyze(s collector.Snapshot) Decision {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.states[AttackConnectionFlood] = d.connFloodSeverity(s)
	d.states[AttackJunkSession] = d.junkSessionSeverity(s)
	d.states[AttackSlowLoris] = d.slowLorisSeverity(s)
	d.states[AttackDictAttack] = d.dictAttackSeverity(s)

	for _, at := range []AttackType{
		AttackConnectionFlood,
		AttackSlowLoris,
		AttackJunkSession,
		AttackDictAttack,
	} {
		if d.states[at] != SeverityNormal {
			return Decision{Attack: at, Severity: d.states[at]}
		}
	}
	return Decision{}
}

func (d *Detector) connFloodSeverity(s collector.Snapshot) Severity {
	t := d.t.ConnectionFlood
	cur := d.states[AttackConnectionFlood]
	switch cur {
	case SeverityCritical:
		if s.ConnRate < t.ConnRateLow {
			return SeverityNormal
		}
		if s.ConnRate < t.ConnRateCrit {
			return SeverityWarning
		}
		return SeverityCritical
	case SeverityWarning:
		if s.ConnRate < t.ConnRateLow {
			return SeverityNormal
		}
		if s.ConnRate >= t.ConnRateCrit {
			return SeverityCritical
		}
		return SeverityWarning
	default:
		if s.ConnRate >= t.ConnRateCrit {
			return SeverityCritical
		}
		if s.ConnRate >= t.ConnRateWarn {
			return SeverityWarning
		}
		return SeverityNormal
	}
}

func (d *Detector) junkSessionSeverity(s collector.Snapshot) Severity {
	t := d.t.JunkSession
	cur := d.states[AttackJunkSession]
	switch cur {
	case SeverityCritical:
		if s.WastedCmdRate < t.WastedCmdRateLow {
			return SeverityNormal
		}
		if s.WastedCmdRate < t.WastedCmdRateCrit {
			return SeverityWarning
		}
		return SeverityCritical
	case SeverityWarning:
		if s.WastedCmdRate < t.WastedCmdRateLow {
			return SeverityNormal
		}
		if s.WastedCmdRate >= t.WastedCmdRateCrit {
			return SeverityCritical
		}
		return SeverityWarning
	default:
		if s.WastedCmdRate >= t.WastedCmdRateCrit {
			return SeverityCritical
		}
		if s.WastedCmdRate >= t.WastedCmdRateWarn {
			return SeverityWarning
		}
		return SeverityNormal
	}
}

func (d *Detector) slowLorisSeverity(s collector.Snapshot) Severity {
	t := d.t.SlowLoris
	cur := d.states[AttackSlowLoris]

	recovered := s.ActiveSessions < t.ActiveSessionsLow || s.TimeoutRate < t.TimeoutRateLow

	switch cur {
	case SeverityCritical:
		if recovered {
			return SeverityNormal
		}
		if s.ActiveSessions < t.ActiveSessionsCrit {
			return SeverityWarning
		}
		return SeverityCritical
	case SeverityWarning:
		if recovered {
			return SeverityNormal
		}
		if s.ActiveSessions >= t.ActiveSessionsCrit && s.TimeoutRate >= t.TimeoutRateTrigger {
			return SeverityCritical
		}
		return SeverityWarning
	default:
		if s.ActiveSessions >= t.ActiveSessionsCrit && s.TimeoutRate >= t.TimeoutRateTrigger {
			return SeverityCritical
		}
		if s.ActiveSessions >= t.ActiveSessionsWarn && s.TimeoutRate >= t.TimeoutRateTrigger {
			return SeverityWarning
		}
		return SeverityNormal
	}
}

func (d *Detector) dictAttackSeverity(s collector.Snapshot) Severity {
	t := d.t.DictAttack

	if s.ConnRate >= t.ConnRateMax {
		return SeverityNormal
	}

	cur := d.states[AttackDictAttack]
	switch cur {
	case SeverityCritical:
		if s.NoqueueRate < t.NoqueueRateLow {
			return SeverityNormal
		}
		if s.NoqueueRate < t.NoqueueRateCrit {
			return SeverityWarning
		}
		return SeverityCritical
	case SeverityWarning:
		if s.NoqueueRate < t.NoqueueRateLow {
			return SeverityNormal
		}
		if s.NoqueueRate >= t.NoqueueRateCrit {
			return SeverityCritical
		}
		return SeverityWarning
	default:
		if s.NoqueueRate >= t.NoqueueRateCrit {
			return SeverityCritical
		}
		if s.NoqueueRate >= t.NoqueueRateWarn {
			return SeverityWarning
		}
		return SeverityNormal
	}
}
