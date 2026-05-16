package collector

import (
	"regexp"
	"strconv"
	"time"
)

var (
	reConnect    = regexp.MustCompile(`postfix/smtpd\[\d+\]: connect from `)
	reDisconnect = regexp.MustCompile(`postfix/smtpd\[\d+\]: disconnect from `)
	reMailCount  = regexp.MustCompile(`\bmail=(\d+)\b`)
	reCmdCount   = regexp.MustCompile(`\bcommands=(?:\d+/)?(\d+)\b`)
	reNoqueue    = regexp.MustCompile(`postfix/smtpd\[\d+\]: NOQUEUE: reject`)
	reTimeout    = regexp.MustCompile(`postfix/smtpd\[\d+\]: timeout after`)
	reNonSmtp    = regexp.MustCompile(`postfix/smtpd\[\d+\]: warning: non-SMTP command`)
)

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
		return Event{At: now, Type: EvDisconnect, Commands: 1, Mail: 0}, true
	}

	return Event{}, false
}
