// Package actuator применяет защитные меры Postfix через канал postfix-ctl.
package actuator

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ConnectionFloodActConfig — параметры смягчения для connection_flood.
type ConnectionFloodActConfig struct {
	// Лимит = ceil(baseline_conn_rate * 60 * multiplier)
	RateLimitMultiplierWarn float64 `yaml:"rate_limit_multiplier_warn"`
	RateLimitMultiplierCrit float64 `yaml:"rate_limit_multiplier_crit"`
	// Нижняя граница лимита (соединений/мин), чтобы не срубить трафик при низком baseline.
	RateLimitMin int `yaml:"rate_limit_min"`
}

// SlowLorisActConfig — параметры смягчения для slow_loris.
type SlowLorisActConfig struct {
	// smtpd_per_record_deadline = yes меняет семантику smtpd_timeout:
	// таймер считается до конца целой SMTP-команды, а не до следующего байта.
	// Это ломает slow-loris стратегию "слать по байту раз в N секунд".
	TimeoutWarnSec      int `yaml:"timeout_warn_sec"`       // smtpd_timeout при Warning
	TimeoutCritSec      int `yaml:"timeout_crit_sec"`       // smtpd_timeout при Critical
	ConnCountLimitWarn  int `yaml:"conn_count_limit_warn"`  // smtpd_client_connection_count_limit при Warning
	ConnCountLimitCrit  int `yaml:"conn_count_limit_crit"`  // smtpd_client_connection_count_limit при Critical
}

// JunkSessionActConfig — параметры смягчения для junk_session.
type JunkSessionActConfig struct {
	HardErrorLimitWarn int `yaml:"hard_error_limit_warn"` // smtpd_hard_error_limit при Warning
	HardErrorLimitCrit int `yaml:"hard_error_limit_crit"` // smtpd_hard_error_limit при Critical
}

// DictAttackActConfig — параметры смягчения для dict_attack.
type DictAttackActConfig struct {
	// smtpd_error_sleep_time = clamp(ceil(noqueue_rate / divisor), min, max)
	ErrorSleepDivisor float64 `yaml:"error_sleep_divisor"`
	ErrorSleepMinSec  int     `yaml:"error_sleep_min_sec"`
	ErrorSleepMaxSec  int     `yaml:"error_sleep_max_sec"`
}

// Config — конфигурация actuator'а.
type Config struct {
	// α для EMA базовой линии: ближе к 1 — быстрее адаптируется, ближе к 0 — стабильнее.
	BaselineAlpha   float64                  `yaml:"baseline_alpha"`
	ConnectionFlood ConnectionFloodActConfig `yaml:"connection_flood"`
	SlowLoris       SlowLorisActConfig       `yaml:"slow_loris"`
	JunkSession     JunkSessionActConfig     `yaml:"junk_session"`
	DictAttack      DictAttackActConfig      `yaml:"dict_attack"`
}

// DefaultConfig возвращает конфигурацию actuator'а по умолчанию.
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

// fileWrapper используется для парсинга секции actuator из общего YAML-файла.
// Секции detector'а (connection_flood, slow_loris и т.д.) при этом игнорируются.
type fileWrapper struct {
	Actuator Config `yaml:"actuator"`
}

// LoadConfigFromFile загружает конфигурацию actuator'а из YAML-файла.
// Файл может содержать как секцию actuator, так и пороги detector'а.
// Поля, не указанные в секции actuator, берутся из DefaultConfig().
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
