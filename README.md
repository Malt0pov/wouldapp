# WOULD VPN Client 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Material Design 3](https://img.shields.io/badge/Design-Material%203-7c3aed.svg)](https://m3.material.io/)
[![Core: Sing-box](https://img.shields.io/badge/Core-Sing--box%201.10-10b981.svg)](https://github.com/SagerNet/sing-box)

**WOULD VPN** — современный, быстрый и минималистичный кроссплатформенный VPN-клиент нового поколения, созданный по строгим гайдлайнам **Google Material Design 3 (Material You)** на базе мощного сетевого ядра **Sing-box**.

---

## ✨ Ключевые возможности

* **🎨 Чистый дизайн Material 3:**
  * Полная адаптивность под **Android** и **Windows 11**.
  * Поддержка 3 тем оформления: *Material You Navy*, *AMOLED Deep Black* (для OLED-экранов), *Light Clean M3*.
  * Тактильный звуковой отклик и плавные микро-анимации.
* **⚡ Сетевое ядро Sing-box Core:**
  * Поддержка новейших протоколов обхода блокировок: **VLESS Reality**, **Hysteria 2**, **TUIC**, **Trojan TLS**, **Shadowsocks 2022**.
  * Полноценный режим **TUN (Wintun адаптер)** — прозрачный перехват 100% системного трафика ПК и приложений.
  * Плавное и безопасное переключение узлов без утечек DNS (*Graceful Reconnect*).
* **📊 Живая телеметрия (60 FPS):**
  * Динамический график сетевой активности на базе HTML5 Canvas.
  * Мониторинг скорости в реальном времени (Download / Upload MB/s) и учет времени сессии.
* **🛠️ Управление серверами:**
  * Быстрый поиск серверов по стране и протоколу.
  * Замер пинга всех серверов в 1 клик (*Real TCP Handshake* / *HTTP 204*).
  * Сортировка узлов по минимальной задержке.
  * Удобный импорт по ссылке (`vless://`, `hysteria2://`, подписки) и через QR-код.
* **🔒 Безопасность и приватность:**
  * Встроенный **Kill Switch** (мгновенная блокировка трафика при обрыве туннеля).
  * Защита от утечек IPv6 и изоляция DNS.
  * Поддержка DNS over HTTPS (DoH Cloudflare + AdGuard фильтрация рекламы).

---

## 🚀 Быстрый запуск (Превью)

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/USERNAME/would-vpn-client.git
   cd would-vpn-client
   ```
2. Запустите локальный сервер:
   ```bash
   node server.js
   ```
3. Откройте в браузере: `http://localhost:3005`

---

## 📄 Лицензия

Проект распространяется под свободной лицензией **MIT License**.
Подробности в файле [LICENSE](LICENSE).
