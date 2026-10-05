import sys
import os
import json
from collections import Counter

def analyze_nuclei(file_path):
    severity_counter = Counter()
    vulnerabilities_details = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                info_block = data.get("info", {})
                severity = info_block.get("severity", "info").lower()
                
                severity_counter[severity] += 1
                
                classification = info_block.get("classification", {})
                cve = classification.get("cve-id")
                cwe_list = classification.get("cwe-id")
                
                vulnerabilities_details.append({
                    "id": data.get("template-id"),
                    "host": data.get("host", "N/A"),
                    "severity": severity.upper(),
                    "cve": cve if cve else "No-CVE",
                    "cwe": ", ".join(cwe_list) if cwe_list else "No-CWE"
                })
            except Exception as e:
                print(f"[!] Ошибка парсинга строки Nuclei: {e}")
    return severity_counter, vulnerabilities_details

def analyze_xsstrike(file_path):
    # XSStrike (XSS)
    pass

def analyze_sqlmap(file_path):
    # SQLMap
    pass

def main():
    if len(sys.argv) < 2:
        print(" Ошибка: Не указан путь к файлу с результатами DAST.")
        print(f" Использование: python3 {os.path.basename(sys.argv[0])} <путь_к_файлу.json>")
        sys.exit(1)

    # Первый аргумент — куда сохранять итоговый отчет
    artifact_file = "security-summary.json"
    # Все остальные аргументы — это список входных файлов для анализа
    input_files = sys.argv[1:]

    # Инициализируем общие счетчики для объединения результатов
    total_stats = Counter({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    all_vulnerabilities = []

    # обходим каждый переданный файл
    for file_path in input_files:
        if not os.path.exists(file_path):
            print(f" Предупреждение: Файл '{file_path}' не найден, пропускаем.")
            continue

        print(f" Анализируем файл: {file_path}")
        # Парсим текущий файл
        stats, details = analyze_nuclei(file_path)
        
        print("\n[+] ДЕТАЛИЗАЦИЯ НАЙДЕННЫХ УЯЗВИМОСТЕЙ:")
        print(f"{'КРИТИЧНОСТЬ':<12} | {'ИДЕНТИФИКАТОР (ID)':<35} | {'ХОСТ':<20} | {'CVE / CWE'}")
        print("-" * 100)
        for vuln in details:
            print(f"{vuln['severity']:<12} | {vuln['id']:<35} | {vuln['host']:<20} | {vuln['cve']} [{vuln['cwe']}]")
        print("=" * 100)
    
        # Объединяем статистику и дефекты в общие массивы
        total_stats.update(stats)
        all_vulnerabilities.extend(details)

    print("\n[+] ОБЩЕЕ КОЛИЧЕСТВО УЯЗВИМОСТЕЙ ПО КРИТИЧНОСТИ:")
    severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
    for sev in severity_order:
        print(f"   * {sev.upper():<9}: {total_stats[sev]}")

    # структура объединенного JSON-артефакта
    total_vulns = sum([total_stats["critical"], total_stats["high"], total_stats["medium"], total_stats["low"], total_stats["info"], total_stats["unknown"]])
    vulns_found = total_vulns > 0

    artifact_data = {
        "scan_type": "DAST_COMBINED_REPORT",
        "vulnerabilities_found": vulns_found,
        "summary": {
            "total_issues": len(all_vulnerabilities),
            "total_vulnerabilities": total_vulns,  # Без учета info логов
            "counts": dict(total_stats)
        },
        "vulnerabilities": all_vulnerabilities
    }

    # объединенный артефакт в файл
    try:
        with open(artifact_file, "w", encoding="utf-8") as art_f:
            json.dump(artifact_data, art_f, indent=4, ensure_ascii=False)
        print(f"\n Объединенный артефакт успешно сохранен в: {artifact_file}")
    except Exception as e:
        print(f" Ошибка при сохранении файла артефакта: {e}")
        
    # БЛОКИРОВКИ СБОРКИ
    # если найдено хотя бы одно CRITICAL или HIGH
    fail_threshold_triggered = total_stats["critical"] > 0 or total_stats["high"] > 0

    if fail_threshold_triggered:
        print("\n СБОРКА ЗАБЛОКИРОВАНА: Обнаружены критические уязвимости (CRITICAL/HIGH)!")
        sys.exit(1)
    else:
        print("\n СБОРКА РАЗРЕШЕНА: Критических угроз не обнаружено.")
        sys.exit(0)

if __name__ == "__main__":
    main()

