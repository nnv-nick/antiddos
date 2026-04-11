#!/bin/bash
set -e

# Создаём необходимые директории и файлы
mkdir -p /var/log /var/spool/postfix /var/lib/postfix
touch /var/log/mail.log
chown syslog:adm /var/log/mail.log

# Запускаем rsyslog для записи логов
rsyslogd

# Инициализируем Postfix
postfix check
postfix start-fg
