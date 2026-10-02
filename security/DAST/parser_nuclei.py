import sys
import os
import json
from collections import Counter

# Проверяем, передан ли аргумент пути к файлу
if len(sys.argv) < 2:
    print("Ошибка: Не указан путь к файлу с результатами Nuclei.")
    print(f"Использование: python3 {os.path.basename(sys.argv[0])} <путь_к_файлу.json>")
    sys.exit(1)

# Получаем путь к файлу из аргументов командной строки
FILE_PATH = sys.argv[1]

# Проверяем, существует ли указанный файл на диске
if not os.path.exists(FILE_PATH):
    print(f"Ошибка: Файл по пути '{FILE_PATH}' не найден.")
    sys.exit(1)

# Счётчик для общей статистики по критичности
severity_counter = Counter()

# Список для хранения детальной информации
vulnerabilities_details = []

print("=" * 80)
print("АНАЛИЗ РЕЗУЛЬТАТОВ СКАНИРОВАНИЯ NUCLEI")
print("=" * 80)

# Построчно читаем JSONL-файл
with open(FILE_PATH, "r", encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            # Извлекаем основные данные
            template_id = data.get("template-id")
            host = data.get("host", "N/A")
            info_block = data.get("info", {})
            severity = info_block.get("severity", "info").lower()
            
            # Считаем количество для общей статистики
            severity_counter[severity] += 1
            
            # Извлекаем CVE и CWE блок классификации
            classification = info_block.get("classification", {})
            cve = classification.get("cve-id")
            cwe_list = classification.get("cwe-id")
            
            # Форматируем вывод CVE/CWE, если они null/пустые
            cve_str = cve if cve else "No-CVE"
            cwe_str = ", ".join(cwe_list) if cwe_list else "No-CWE"
            
            vulnerabilities_details.append({
                "id": template_id,
                "host": host,
                "severity": severity.upper(),
                "cve": cve_str,
                "cwe": cwe_str
            })
        except Exception as e:
            print(f"[!] Ошибка парсинга строки: {e}")

# 1. Выводим общую статистику (количество)
print("\n[+] ОБЩЕЕ КОЛИЧЕСТВО УЯЗВИМОСТЕЙ ПО КРИТИЧНОСТИ:")
order = ["critical", "high", "medium", "low", "info", "unknown"]
for sev in order:
    count = severity_counter[sev]
    print(f"  {sev.upper():<9}: {count}")

# 2. Выводим детализированную таблицу
print("\n[+] ДЕТАЛИЗАЦИЯ НАЙДЕННЫХ УЯЗВИМОСТЕЙ:")
print(f"{'КРИТИЧНОСТЬ':<12} | {'ИДЕНТИФИКАТОР (ID)':<35} | {'ХОСТ':<20} | {'CVE / CWE'}")
print("-" * 100)

for vuln in vulnerabilities_details:
    print(f"{vuln['severity']:<12} | {vuln['id']:<35} | {vuln['host']:<20} | {vuln['cve']} [{vuln['cwe']}]")

print("=" * 100)

