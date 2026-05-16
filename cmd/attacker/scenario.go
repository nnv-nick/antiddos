package main

import "time"

type Scenario struct {
	Name        string  `yaml:"name"`
	Description string  `yaml:"description"`
	Phases      []Phase `yaml:"phases"`
}

type Phase struct {
	Name     string        `yaml:"name"`
	Duration time.Duration `yaml:"duration"`
	Attack   AttackConfig  `yaml:"attack"`
}

type AttackConfig struct {
	Type                   string   `yaml:"type"`
	Workers                int      `yaml:"workers"`
	RatePerSec             float64  `yaml:"rate_per_sec"`
	SenderIPs              []string `yaml:"sender_ips"`
	SenderDomains          []string `yaml:"sender_domains"`
	RcptPerSession         int      `yaml:"rcpt_per_session"`
	JunkCommandsPerSession int      `yaml:"junk_commands_per_session"`
	SlowLorisDelayMs       int      `yaml:"slow_loris_delay_ms"`
}
