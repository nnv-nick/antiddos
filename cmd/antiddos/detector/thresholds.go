package detector

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ConnectionFloodThresholds struct {
	ConnRateWarn float64 `yaml:"conn_rate_warn"`
	ConnRateCrit float64 `yaml:"conn_rate_crit"`
	ConnRateLow  float64 `yaml:"conn_rate_low"`
}

type JunkSessionThresholds struct {
	WastedCmdRateWarn float64 `yaml:"wasted_cmd_rate_warn"`
	WastedCmdRateCrit float64 `yaml:"wasted_cmd_rate_crit"`
	WastedCmdRateLow  float64 `yaml:"wasted_cmd_rate_low"`
}

type SlowLorisThresholds struct {
	ActiveSessionsWarn int     `yaml:"active_sessions_warn"`
	ActiveSessionsCrit int     `yaml:"active_sessions_crit"`
	ActiveSessionsLow  int     `yaml:"active_sessions_low"`
	TimeoutRateTrigger float64 `yaml:"timeout_rate_trigger"`
	TimeoutRateLow     float64 `yaml:"timeout_rate_low"`
}

type DictAttackThresholds struct {
	NoqueueRateWarn float64 `yaml:"noqueue_rate_warn"`
	NoqueueRateCrit float64 `yaml:"noqueue_rate_crit"`
	NoqueueRateLow  float64 `yaml:"noqueue_rate_low"`
	ConnRateMax     float64 `yaml:"conn_rate_max"`
}

type Thresholds struct {
	ConnectionFlood ConnectionFloodThresholds `yaml:"connection_flood"`
	JunkSession     JunkSessionThresholds     `yaml:"junk_session"`
	SlowLoris       SlowLorisThresholds       `yaml:"slow_loris"`
	DictAttack      DictAttackThresholds      `yaml:"dict_attack"`
}

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
