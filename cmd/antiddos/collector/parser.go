package collector

import (
	"regexp"
	"strconv"
	"time"
)

var (
	reConnect = regexp.MustCompile(`postfix/smtpd\[\d+\]: connect from `)

	// disconnect from unknown[1.2.3.4] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5
	reDisconnect = regexp.MustCompile(`postfix/smtpd\[\d+\]: disconnect from `)
	reMailCount  = regexp.MustCompile(`\bmail=(\d+)\b`)
	reCmdCount   = regexp.MustCompile(`\bcommands=(\d+)\b`)

	reNoqueue = regexp.MustCompile(`postfix/smtpd\[\d+\]: NOQUEUE: reject`)
	reTimeout = regexp.MustCompile(`postfix/smtpd\[\d+\]: timeout after`)
	reNonSmtp = regexp.MustCompile(`postfix/smtpd\[\d+\]: warning: non-SMTP command`)
)

// ParseLine разбирает одну строку mail.log.
// Возвращает (Event, true) если строка релевантна, (zero, false) иначе.
// Временна́я метка события выставляется в time.Now() в момент вызова.
func ParseLine(line string) (Event, bool) {
	now := time.Now()

	switch {
	case reConnect.MatchString(line):
		return Event{At: now, Type: EvConnect}, true

	case reDisconnect.MatchString(line):
		e := Event{At: now, Type: EvDisconnect}
		if m := reCmdCount.FindStringSubmatch(line); m != nil {
			e.Commands, _ = strconv.Atoi(m[1])
		}
		if m := reMailCount.FindStringSubmatch(line); m != nil {
			e.Mail, _ = strconv.Atoi(m[1])
		}
		return e, true

	case reNoqueue.MatchString(line):
		return Event{At: now, Type: EvNoqueue}, true

	case reTimeout.MatchString(line):
		return Event{At: now, Type: EvTimeout}, true

	case reNonSmtp.MatchString(line):
		// Трактуем как disconnect-без-mail: соединение занято, письма нет.
		// commands=1 (сама невалидная команда) для корректного wasted_cmd_rate.
		return Event{At: now, Type: EvDisconnect, Commands: 1, Mail: 0}, true
	}

	return Event{}, false
}
