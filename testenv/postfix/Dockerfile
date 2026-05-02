FROM ubuntu:24.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postfix rsyslog netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY main.cf /etc/postfix/main.cf
COPY master.cf /etc/postfix/master.cf
COPY relay_recipients /etc/postfix/relay_recipients

# rsyslog пишет mail.log, Postfix читает его
COPY rsyslog.conf /etc/rsyslog.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25

ENTRYPOINT ["/entrypoint.sh"]
