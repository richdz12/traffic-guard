# TrafficGuard

Утилита для блокировки сканеров портов через iptables и ipset с поддержкой логирования и агрегации статистики.

## Установка

### Автоматическая установка

Скачайте и запустите установочный скрипт:

```bash
curl -fsSL https://raw.githubusercontent.com/dotX12/traffic-guard/master/install.sh | sudo bash
```

или

```bash
wget -qO- https://raw.githubusercontent.com/dotX12/traffic-guard/master/install.sh | sudo bash
```

Скрипт автоматически:
- Определит архитектуру системы (amd64, 386, arm, arm64)
- Скачает последний релиз для вашей системы
- Установит бинарник в `/usr/local/bin`
- Выдаст права на выполнение

### Ручная установка

1. Скачайте нужный бинарник из [последнего релиза](https://github.com/dotX12/traffic-guard/releases/latest):
   - `traffic-guard-linux-amd64` - для 64-битных систем
   - `traffic-guard-linux-386` - для 32-битных систем
   - `traffic-guard-linux-arm` - для ARM
   - `traffic-guard-linux-arm64` - для ARM64

2. Установите:
```bash
sudo mv traffic-guard-linux-* /usr/local/bin/traffic-guard
sudo chmod +x /usr/local/bin/traffic-guard
```

## Возможности

- 📥 Скачивание списков подсетей сканеров из внешних источников
- 🛡️ Автоматическая настройка iptables/ip6tables правил
- 📊 Управление ipset наборами для IPv4 и IPv6
- 📝 Легковесное логирование с агрегацией (опционально)
- 🔄 Автоматическое сохранение правил для применения после перезагрузки

## Использование

### ⚠️ Важно

**Обязательно** необходимо передать один или несколько URL с списками подсетей через параметр `-u`:

```bash
sudo traffic-guard full -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list
```

Можно указать несколько источников:

```bash
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list \
  --enable-logging
```

### Публичные списки

Готовые списки подсетей сканеров доступны в репозитории: 
**[shadow-netlab/traffic-guard-lists](https://github.com/shadow-netlab/traffic-guard-lists/tree/main)**

Доступные списки:
- `public/antiscanner.list` - список от **[zakachkin/AntiScanner](https://github.com/zakachkin/AntiScanner)**
- `public/government_networks.list` - подсети различных сканеров государственных организаций

### Примеры использования

Базовая блокировка без логирования:

```bash
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list
```

С включенным логированием:

```bash
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list \
  --enable-logging
```

### Опции

- **`-u, --urls`** (обязательно) - URL для скачивания подсетей. Можно указать несколько раз
- `-l, --enable-logging` - включить логирование заблокированных подключений
- `--log-level` - уровень логирования (debug, info, warn, error). По умолчанию: info

## Логирование

### Конфигурация

При включении логирования (`--enable-logging`) создаются:

1. **`/etc/rsyslog.d/10-iptables-scanners.conf`** - конфигурация rsyslog
2. **`/etc/logrotate.d/iptables-scanners`** - ротация логов (каждый час, хранится 2 часа)
3. **`/usr/local/bin/antiscan-aggregate-logs.sh`** - скрипт агрегации
4. **`/etc/systemd/system/antiscan-aggregate.service`** - systemd service
5. **`/etc/systemd/system/antiscan-aggregate.timer`** - systemd timer (каждые 10 секунд)

### Файлы логов

- **`/var/log/iptables-scanners-ipv4.log`** - сырые логи IPv4 (обрабатываются каждые 30 сек)
- **`/var/log/iptables-scanners-ipv6.log`** - сырые логи IPv6 (обрабатываются каждые 30 сек)
- **`/var/log/iptables-scanners-aggregate.csv`** - агрегированная статистика в CSV формате

### Формат агрегированного CSV

Файл `/var/log/iptables-scanners-aggregate.csv` содержит статистику с автоматическим whois lookup:

```csv
IP_TYPE|IP_ADDRESS|ASN|NETNAME|COUNT|LAST_SEEN
v4|85.142.100.138|AS49505|JSCCYBEROK-NET|237|2026-01-25T17:08:01.123456+03:00
v6|2001:db8::1|AS12345|EXAMPLE-NET|12|2026-01-25T17:08:05.987654+03:00
```

**Поля:**
- `IP_TYPE` - тип IP (v4/v6)
- `IP_ADDRESS` - IP адрес сканера
- `ASN` - номер автономной системы (из whois)
- `NETNAME` - имя сети (из whois)
- `COUNT` - количество попыток подключения
- `LAST_SEEN` - время последней попытки

**Особенности:**
- Whois lookup с кэшированием (не повторяется для одного IP)
- Таймаут lookup: 3 секунды
- CSV отсортирован по COUNT (самые активные сверху)

### Лимиты логирования

- Максимум **10 записей в минуту** на каждый IP (чтобы не засорять логи)
- Топ-50 активных IP в каждом интервале агрегации

### Просмотр логов

```bash
# Последние агрегированные данные
tail -f /var/log/iptables-scanners-aggregate.log

# Статус systemd timer
systemctl status antiscan-aggregate.timer

# Логи агрегатора
journalctl -u antiscan-aggregate.service -f
```

## Что создается в системе

### iptables

- **Цепочка**: `SCANNERS-BLOCK`
- **Правила**: 
  - IPv4: `INPUT -j SCANNERS-BLOCK`
  - IPv6: `INPUT -j SCANNERS-BLOCK`
  - `SCANNERS-BLOCK -m set --match-set SCANNERS-BLOCK-V4 src -j DROP` (IPv4)
  - `SCANNERS-BLOCK -m set --match-set SCANNERS-BLOCK-V6 src -j DROP` (IPv6)

С логированием добавляются дополнительные правила с rate-limit.

### ipset

- **Наборы**:
  - `SCANNERS-BLOCK-V4` - hash:net для IPv4
  - `SCANNERS-BLOCK-V6` - hash:net для IPv6
- **Конфигурация**: `/etc/ipset.conf`

### Автозагрузка

Правила автоматически сохраняются:
- **Debian/Ubuntu**: `/etc/iptables/rules.v4`, `/etc/iptables/rules.v6`
- **RedHat/CentOS**: через `service iptables save`

## Лицензия

MIT