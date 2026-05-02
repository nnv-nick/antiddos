#!/bin/bash
set -e

# Создаём необходимые директории и файлы
mkdir -p /var/log /var/spool/postfix /var/lib/postfix
# Сбрасываем лог при старте: postfix-exporter считает queue_depth из лога,
# и без сброса метрика расходится с реальностью после перезапуска контейнера.
: > /var/log/mail.log
chown syslog:adm /var/log/mail.log

# Создаём директорию для команд от antiddos
mkdir -p /postfix-ctl

# Запускаем rsyslog для записи логов
rsyslogd

# Watchdog: применяет команды от actuator'а.
# Ждёт появления файла /postfix-ctl/reload, читает /postfix-ctl/antiddos.cf
# и перезагружает Postfix с новыми параметрами.
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

# Копируем resolv.conf в chroot Postfix, иначе smtp-клиент не резолвит хосты
mkdir -p /var/spool/postfix/etc
cp /etc/resolv.conf /var/spool/postfix/etc/resolv.conf

# Генерируем hash-таблицу для relay_recipient_maps
postmap /etc/postfix/relay_recipients

# Инициализируем Postfix
postfix check
postfix start-fg
