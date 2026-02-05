# Advanced Traffic Analyzer

CLI-скрипт для анализа логов веб-сервера с фильтрацией и агрегацией.

---

## Формат логов

Каждая строка:

<timestamp> <ip_address> <http_method> <url> <status_code> <response_size>

Пример:

1717020800 192.168.1.10 GET /home 200 1500

---

## Запуск

Базовый запуск:

python advanced_traffic_analyzer.py sample_access.log

---

## Аргументы

--method <METHOD>  
Фильтр по HTTP-методу

--status <CODE | RANGE>  
Пример:
--status 200  
--status 400-499

--start <TIMESTAMP>  
Начало интервала

--end <TIMESTAMP>  
Конец интервала

--top <N>  
Топ IP (по умолчанию 3)

---

## Примеры

python advanced_traffic_analyzer.py sample_access.log --method GET

python advanced_traffic_analyzer.py sample_access.log --status 400-499

python advanced_traffic_analyzer.py sample_access.log --top 10

python advanced_traffic_analyzer.py sample_access.log --method POST --status 500-599

---

## Что считает

- Общее число запросов  
- Уникальные IP  
- Топ IP  
- Распределение методов  
- Топ URL  
- Объём данных  
- Ошибки 4xx/5xx  
- Средний размер 2xx  
- Активность за последние 24 часа  

---

## Алгоритм

2 прохода по файлу:

1. Глобальная статистика + максимальный timestamp  
2. Статистика за последние 24 часа  

---

## Сложность

Время: O(n)  
Память: O(U + I)

Подходит для файлов до ~1,000,000 строк.
