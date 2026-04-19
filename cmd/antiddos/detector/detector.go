package detector

import (
	"sync"

	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
)

// AttackType классифицирует тип обнаруженной атаки.
type AttackType int

const (
	AttackNone           AttackType = iota
	AttackConnectionFlood           // флуд соединениями
	AttackJunkSession               // мусорные сессии (mail=0)
	AttackSlowLoris                 // медленные соединения
	AttackDictAttack                // перебор получателей

	attackTypeCount // sentinel для размера массива
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

// Severity описывает серьёзность обнаруженной атаки.
type Severity int

const (
	SeverityNormal   Severity = iota
	SeverityWarning           // метрика превысила мягкий порог
	SeverityCritical          // метрика превысила жёсткий порог
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

// Decision — результат анализа одного Snapshot.
type Decision struct {
	Attack   AttackType
	Severity Severity
}

// Detector анализирует Snapshot'ы и классифицирует атаки с гистерезисом.
// Гистерезис предотвращает флаппинг: атака начинается при превышении высокого порога,
// а завершается только когда метрика опускается ниже низкого (Low) порога.
//
// Приоритет при одновременном срабатывании нескольких типов:
// ConnectionFlood > SlowLoris > JunkSession > DictAttack.
type Detector struct {
	t      Thresholds
	mu     sync.Mutex
	states [attackTypeCount]Severity // текущее состояние по каждому типу атаки
}

// New создаёт Detector с заданными порогами.
func New(t Thresholds) *Detector {
	return &Detector{t: t}
}

// Analyze анализирует Snapshot и возвращает Decision.
// Метод потокобезопасен.
func (d *Detector) Analyze(s collector.Snapshot) Decision {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.states[AttackConnectionFlood] = d.connFloodSeverity(s)
	d.states[AttackJunkSession] = d.junkSessionSeverity(s)
	d.states[AttackSlowLoris] = d.slowLorisSeverity(s)
	d.states[AttackDictAttack] = d.dictAttackSeverity(s)

	// Возвращаем атаку с наибольшим приоритетом среди ненормальных
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

// connFloodSeverity вычисляет severity для connection_flood с гистерезисом.
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

// junkSessionSeverity вычисляет severity для junk_session с гистерезисом.
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

// slowLorisSeverity вычисляет severity для slow_loris с гистерезисом.
// Для срабатывания нужны оба условия: ActiveSessions И TimeoutRate выше порогов.
// Для восстановления достаточно, чтобы хотя бы одна метрика упала ниже low-порога.
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

// dictAttackSeverity вычисляет severity для dict_attack с гистерезисом.
// Если ConnRate выше ConnRateMax — это connection_flood, а не dict_attack.
func (d *Detector) dictAttackSeverity(s collector.Snapshot) Severity {
	t := d.t.DictAttack

	// Высокий ConnRate означает connection_flood — не смешиваем типы
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
