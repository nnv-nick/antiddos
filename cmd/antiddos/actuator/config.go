package actuator

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ConnectionFloodActConfig struct {
	RateLimitMultiplierWarn float64 `yaml:"rate_limit_multiplier_warn"`
	RateLimitMultiplierCrit float64 `yaml:"rate_limit_multiplier_crit"`
	RateLimitMin            int     `yaml:"rate_limit_min"`
}

type SlowLorisActConfig struct {
	TimeoutWarnSec     int `yaml:"timeout_warn_sec"`
	TimeoutCritSec     int `yaml:"timeout_crit_sec"`
	ConnCountLimitWarn int `yaml:"conn_count_limit_warn"`
	ConnCountLimitCrit int `yaml:"conn_count_limit_crit"`
}

type JunkSessionActConfig struct {
	HardErrorLimitWarn int `yaml:"hard_error_limit_warn"`
	HardErrorLimitCrit int `yaml:"hard_error_limit_crit"`
}

type DictAttackActConfig struct {
	ErrorSleepDivisor float64 `yaml:"error_sleep_divisor"`
	ErrorSleepMinSec  int     `yaml:"error_sleep_min_sec"`
	ErrorSleepMaxSec  int     `yaml:"error_sleep_max_sec"`
}

type Config struct {
	BaselineAlpha   float64                  `yaml:"baseline_alpha"`
	ConnectionFlood ConnectionFloodActConfig `yaml:"connection_flood"`
	SlowLoris       SlowLorisActConfig       `yaml:"slow_loris"`
	JunkSession     JunkSessionActConfig     `yaml:"junk_session"`
	DictAttack      DictAttackActConfig      `yaml:"dict_attack"`
}

func DefaultConfig() Config {
	return Config{
		BaselineAlpha: 0.1,
		ConnectionFlood: ConnectionFloodActConfig{
			RateLimitMultiplierWarn: 2.0,
			RateLimitMultiplierCrit: 1.2,
			RateLimitMin:            5,
		},
		SlowLoris: SlowLorisActConfig{
			TimeoutWarnSec:     30,
			TimeoutCritSec:     10,
			ConnCountLimitWarn: 5,
			ConnCountLimitCrit: 3,
		},
		JunkSession: JunkSessionActConfig{
			HardErrorLimitWarn: 10,
			HardErrorLimitCrit: 5,
		},
		DictAttack: DictAttackActConfig{
			ErrorSleepDivisor: 5.0,
			ErrorSleepMinSec:  1,
			ErrorSleepMaxSec:  10,
		},
	}
}

type fileWrapper struct {
	Actuator Config `yaml:"actuator"`
}

func LoadConfigFromFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	w := fileWrapper{Actuator: DefaultConfig()}
	if err := yaml.Unmarshal(data, &w); err != nil {
		return Config{}, err
	}
	return w.Actuator, nil
}
