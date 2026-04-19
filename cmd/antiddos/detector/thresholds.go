// Package detector анализирует Snapshot от collector'а и классифицирует атаки.
package detector

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ConnectionFloodThresholds — пороги для детекции флуда соединениями.
type ConnectionFloodThresholds struct {
	ConnRateWarn float64 `yaml:"conn_rate_warn"` // новых соединений/с → Warning
	ConnRateCrit float64 `yaml:"conn_rate_crit"` // новых соединений/с → Critical
	ConnRateLow  float64 `yaml:"conn_rate_low"`  // гистерезис: возврат в Normal
}

// JunkSessionThresholds — пороги для детекции мусорных сессий.
type JunkSessionThresholds struct {
	WastedCmdRateWarn float64 `yaml:"wasted_cmd_rate_warn"` // команд в сессиях mail=0, /с → Warning
	WastedCmdRateCrit float64 `yaml:"wasted_cmd_rate_crit"` // → Critical
	WastedCmdRateLow  float64 `yaml:"wasted_cmd_rate_low"`  // гистерезис
}

// SlowLorisThresholds — пороги для детекции slow loris.
// Обе метрики (active_sessions И timeout_rate) должны превышать пороги для срабатывания.
// Для восстановления достаточно, чтобы хоть одна упала ниже low-порога.
type SlowLorisThresholds struct {
	ActiveSessionsWarn int     `yaml:"active_sessions_warn"` // активных сессий → Warning
	ActiveSessionsCrit int     `yaml:"active_sessions_crit"` // → Critical
	ActiveSessionsLow  int     `yaml:"active_sessions_low"`  // гистерезис
	TimeoutRateTrigger float64 `yaml:"timeout_rate_trigger"` // вторичное условие: таймаутов/с
	TimeoutRateLow     float64 `yaml:"timeout_rate_low"`     // гистерезис для вторичного условия
}

// DictAttackThresholds — пороги для детекции перебора получателей.
// Срабатывает при высоком NoqueueRate И умеренном ConnRate (иначе — connection_flood).
type DictAttackThresholds struct {
	NoqueueRateWarn float64 `yaml:"noqueue_rate_warn"` // NOQUEUE-отказов/с → Warning
	NoqueueRateCrit float64 `yaml:"noqueue_rate_crit"` // → Critical
	NoqueueRateLow  float64 `yaml:"noqueue_rate_low"`  // гистерезис
	ConnRateMax     float64 `yaml:"conn_rate_max"`     // выше этого — connection_flood, не dict_attack
}

// Thresholds — все пороги для всех типов атак.
type Thresholds struct {
	ConnectionFlood ConnectionFloodThresholds `yaml:"connection_flood"`
	JunkSession     JunkSessionThresholds     `yaml:"junk_session"`
	SlowLoris       SlowLorisThresholds       `yaml:"slow_loris"`
	DictAttack      DictAttackThresholds      `yaml:"dict_attack"`
}

// DefaultThresholds возвращает пороги по умолчанию, настроенные для тестовой среды
// с легитимным трафиком ~2 письма/с.
func DefaultThresholds() Thresholds {
	return Thresholds{
		ConnectionFlood: ConnectionFloodThresholds{
			ConnRateWarn: 10.0,
			ConnRateCrit: 30.0,
			ConnRateLow:  5.0,
		},
		JunkSession: JunkSessionThresholds{
			WastedCmdRateWarn: 5.0,
			WastedCmdRateCrit: 15.0,
			WastedCmdRateLow:  2.0,
		},
		SlowLoris: SlowLorisThresholds{
			ActiveSessionsWarn: 20,
			ActiveSessionsCrit: 50,
			ActiveSessionsLow:  10,
			TimeoutRateTrigger: 1.0,
			TimeoutRateLow:     0.5,
		},
		DictAttack: DictAttackThresholds{
			NoqueueRateWarn: 5.0,
			NoqueueRateCrit: 15.0,
			NoqueueRateLow:  2.0,
			ConnRateMax:     10.0,
		},
	}
}

// LoadFromFile загружает пороги из YAML-файла.
// Поля, не указанные в файле, берутся из DefaultThresholds().
func LoadFromFile(path string) (Thresholds, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Thresholds{}, err
	}
	t := DefaultThresholds()
	if err := yaml.Unmarshal(data, &t); err != nil {
		return Thresholds{}, err
	}
	return t, nil
}
