package actuator

import (
	"fmt"
	"math"

	"github.com/nnv-nick/antiddos/cmd/antiddos/collector"
	"github.com/nnv-nick/antiddos/cmd/antiddos/detector"
)

// defaultPostfixLines — параметры Postfix по умолчанию (соответствуют main.cf).
// Применяются при восстановлении после атаки (Attack == AttackNone).
var defaultPostfixLines = []string{
	"smtpd_client_connection_rate_limit = 0",
	"smtpd_hard_error_limit = 20",
	"smtpd_error_sleep_time = 1s",
	"smtpd_timeout = 300s",
	"smtpd_per_record_deadline = no",
	"smtpd_client_connection_count_limit = 50",
}

// ComputeLines вычисляет строки конфигурации Postfix для данного Decision.
// Экспортирована для использования в тестах.
func ComputeLines(dec detector.Decision, snap collector.Snapshot, baseline *EMABaseline, cfg Config) []string {
	switch dec.Attack {
	case detector.AttackConnectionFlood:
		return connFloodLines(dec.Severity, baseline, cfg)
	case detector.AttackJunkSession:
		return junkSessionLines(dec.Severity, cfg)
	case detector.AttackSlowLoris:
		return slowLorisLines(dec.Severity, cfg)
	case detector.AttackDictAttack:
		return dictAttackLines(snap, cfg)
	default:
		return defaultPostfixLines
	}
}

// connFloodLines вычисляет лимит соединений/мин относительно baseline.
// Чем выше baseline (нормальный трафик), тем мягче лимит — легитимные клиенты не страдают.
func connFloodLines(sev detector.Severity, baseline *EMABaseline, cfg Config) []string {
	mult := cfg.ConnectionFlood.RateLimitMultiplierWarn
	if sev == detector.SeverityCritical {
		mult = cfg.ConnectionFlood.RateLimitMultiplierCrit
	}
	limit := int(math.Ceil(baseline.ConnRate * 60 * mult))
	if limit < cfg.ConnectionFlood.RateLimitMin {
		limit = cfg.ConnectionFlood.RateLimitMin
	}
	return []string{
		fmt.Sprintf("smtpd_client_connection_rate_limit = %d", limit),
	}
}

// junkSessionLines снижает smtpd_hard_error_limit — сессии с ошибками быстрее рвутся.
func junkSessionLines(sev detector.Severity, cfg Config) []string {
	limit := cfg.JunkSession.HardErrorLimitWarn
	if sev == detector.SeverityCritical {
		limit = cfg.JunkSession.HardErrorLimitCrit
	}
	return []string{
		fmt.Sprintf("smtpd_hard_error_limit = %d", limit),
	}
}

// slowLorisLines противодействует slow_loris тремя мерами:
//  1. smtpd_per_record_deadline=yes — таймаут применяется к целой SMTP-команде,
//     а не к каждому байту. Стратегия "байт раз в N секунд" перестаёт работать.
//  2. smtpd_timeout — короткий дедлайн на завершение команды.
//  3. smtpd_client_connection_count_limit — ограничивает слоты на один IP.
func slowLorisLines(sev detector.Severity, cfg Config) []string {
	timeout := cfg.SlowLoris.TimeoutWarnSec
	connLimit := cfg.SlowLoris.ConnCountLimitWarn
	if sev == detector.SeverityCritical {
		timeout = cfg.SlowLoris.TimeoutCritSec
		connLimit = cfg.SlowLoris.ConnCountLimitCrit
	}
	return []string{
		"smtpd_per_record_deadline = yes",
		fmt.Sprintf("smtpd_timeout = %ds", timeout),
		fmt.Sprintf("smtpd_client_connection_count_limit = %d", connLimit),
	}
}

// dictAttackLines увеличивает задержку после ошибки пропорционально интенсивности атаки.
// Атакующий с высоким NoqueueRate сам себя тормозит.
func dictAttackLines(snap collector.Snapshot, cfg Config) []string {
	sleep := int(math.Ceil(snap.NoqueueRate / cfg.DictAttack.ErrorSleepDivisor))
	if sleep < cfg.DictAttack.ErrorSleepMinSec {
		sleep = cfg.DictAttack.ErrorSleepMinSec
	}
	if sleep > cfg.DictAttack.ErrorSleepMaxSec {
		sleep = cfg.DictAttack.ErrorSleepMaxSec
	}
	return []string{
		fmt.Sprintf("smtpd_error_sleep_time = %ds", sleep),
	}
}
