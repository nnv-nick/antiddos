# Тестовая среда

## Быстрый старт

```bash
# 1. Поднять инфраструктуру (Postfix, prometheus, grafana, legit-sender)
docker compose up -d

# 2. Открыть Grafana: http://localhost:3000  (admin / admin)
#    Дашборд: AntiDDoS / Postfix AntiDDoS — Overview

# 3. Запустить сценарий атаки
docker compose run --rm attacker --scenario /scenarios/baseline.yaml
docker compose run --rm attacker --scenario /scenarios/s1_vector_switch.yaml
```

## Сценарии

| Файл | Тип | Описание |
|------|-----|----------|
| `baseline.yaml` | — | Без атаки, эталонные метрики |
| `a1_connection_flood_single.yaml` | Базовый | Флуд с одного IP |
| `a2_junk_session.yaml` | Базовый | Невалидные команды в сессии |
| `a3_rcpt_dictionary.yaml` | Базовый | Dictionary-атака RCPT TO |
| `a4_slow_loris.yaml` | Базовый | Slow loris (держим соединения) |
| `s1_vector_switch.yaml` | **Смена вектора** | junk → connection flood |
| `s2_escalation.yaml` | **Смена вектора** | Тихая атака → внезапный рост ×5 |
| `s3_pulsar.yaml` | **Смена вектора** | Волны атак с паузами |
| `s4_camouflage.yaml` | **Смена вектора** | Dictionary → + junk сверху |
| `s5_hysteresis.yaml` | **Смена вектора** | Проверка работы гистерезиса |
| `s6_multiwave.yaml` | **Смена вектора** | 3 разных вектора последовательно |

## Метрики Prometheus

| Метрика | Источник | Значение |
|---------|----------|----------|
| `legit_sender_sent_total` | legit-sender | Писем отправлено |
| `legit_sender_delivered_total` | legit-sender | Писем доставлено (2xx) |
| `legit_sender_rejected_total` | legit-sender | Писем отклонено |
| `legit_sender_latency_seconds` | legit-sender | Гистограмма задержки |
| `attacker_connections_total` | attacker | Соединений открыто |
| `attacker_messages_total` | attacker | Команд/писем отправлено |
| `attacker_phase` | attacker | Текущая фаза сценария |
| `postfix_smtpd_connects_total` | postfix-exporter | Соединений принято |
| `postfix_smtpd_disconnects_total` | postfix-exporter | Соединений закрыто |
