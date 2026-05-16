#!/bin/bash
set -e

mkdir -p /var/log /var/spool/postfix /var/lib/postfix
: > /var/log/mail.log
chown syslog:adm /var/log/mail.log

mkdir -p /postfix-ctl

rsyslogd

watchdog() {
    while true; do
        if [ -f /postfix-ctl/reload ]; then
            rm -f /postfix-ctl/reload
            if [ -f /postfix-ctl/antiddos.cf ]; then
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    postconf -e "$line" && echo "watchdog: applied: $line"
                done < /postfix-ctl/antiddos.cf
            fi
            postfix reload && echo "watchdog: postfix reloaded"
        fi
        sleep 1
    done
}

watchdog &

mkdir -p /var/spool/postfix/etc
cp /etc/resolv.conf /var/spool/postfix/etc/resolv.conf

postmap /etc/postfix/relay_recipients

postfix check
postfix start-fg
