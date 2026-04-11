package main

import "time"

// Scenario описывает полный сценарий атаки, состоящий из фаз.
type Scenario struct {
	Name        string  `yaml:"name"`
	Description string  `yaml:"description"`
	Phases      []Phase `yaml:"phases"`
}

// Phase — одна фаза сценария. По истечении Duration начинается следующая.
type Phase struct {
	Name     string        `yaml:"name"`
	Duration time.Duration `yaml:"duration"`
	Attack   AttackConfig  `yaml:"attack"`
}

// AttackConfig описывает конкретную атаку в рамках фазы.
type AttackConfig struct {
	// Тип атаки: connection_flood | junk_session | rcpt_dictionary |
	//            slow_loris | sender_rotation | no_attack
	Type string `yaml:"type"`

	// Количество параллельных "воркеров" (горутин)
	Workers int `yaml:"workers"`

	// Целевое число соединений или операций в секунду (суммарно по всем воркерам).
	// 0 — без ограничений (максимальная нагрузка).
	RatePerSec float64 `yaml:"rate_per_sec"`

	// Ротация IP-адресов отправителя.
	// Если пусто — используется один фиксированный адрес (контейнер по умолчанию).
	// Формат: список CIDR или конкретных IP, из которых берётся случайный.
	// Примечание: реальная ротация IP требует прав NET_ADMIN; в тестах
	// мы меняем IP в заголовке SMTP (EHLO/MAIL FROM), а не на уровне TCP.
	SenderIPs []string `yaml:"sender_ips"`

	// Ротация MAIL FROM адресов (для sender_rotation и dictionary-атак)
	SenderDomains []string `yaml:"sender_domains"`

	// Количество RCPT TO на одну сессию (для rcpt_dictionary)
	RcptPerSession int `yaml:"rcpt_per_session"`

	// Количество junk-команд на сессию (для junk_session)
	JunkCommandsPerSession int `yaml:"junk_commands_per_session"`

	// Задержка между байтами соединения в мс (для slow_loris)
	SlowLorisDelayMs int `yaml:"slow_loris_delay_ms"`
}
