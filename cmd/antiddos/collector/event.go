package collector

import "time"

type EventType int

const (
	EvConnect    EventType = iota
	EvDisconnect
	EvNoqueue
	EvTimeout
	EvNonSmtp
	EvQueueDepth
)

type Event struct {
	At   time.Time
	Type EventType

	Commands int
	Mail     int

	Depth int
}

type Snapshot struct {
	ConnRate       float64
	ActiveSessions int
	NoqueueRate    float64
	TimeoutRate    float64
	WastedCmdRate  float64
	QueueDepth     int
	At             time.Time
}
