// Package collector собирает события Postfix из mail.log и postqueue,
// агрегирует их в скользящем окне и предоставляет Snapshot детектору.
package collector

import "time"

// EventType идентифицирует тип события Postfix.
type EventType int

const (
	EvConnect    EventType = iota // "connect from"
	EvDisconnect                  // "disconnect from ... commands=N mail=N"
	EvNoqueue                     // "NOQUEUE: reject"
	EvTimeout                     // "timeout after"
	EvNonSmtp                     // "non-SMTP command"
	EvQueueDepth                  // синтетическое: результат опроса postqueue
)

// Event — одно наблюдаемое событие в Postfix.
type Event struct {
	At   time.Time
	Type EventType

	// EvDisconnect: значения из строки "commands=N mail=N"
	Commands int
	Mail     int

	// EvQueueDepth: текущая глубина очереди
	Depth int
}

// Snapshot — срез активности Postfix за скользящее окно.
type Snapshot struct {
	ConnRate       float64   // новых соединений в секунду
	ActiveSessions int       // connect минус disconnect за окно
	NoqueueRate    float64   // NOQUEUE-отказов в секунду
	TimeoutRate    float64   // таймаутов в секунду
	WastedCmdRate  float64   // команд в сессиях с mail=0, в секунду
	QueueDepth     int       // последнее значение от poller'а
	At             time.Time // момент снятия снимка
}
