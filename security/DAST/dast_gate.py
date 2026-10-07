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

def analyze_zap(file_path):
    severity_counter = Counter({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    vulnerabilities_details = []
    zap_severity_mapping = {
        "3": "high",
        "2": "medium",
        "1": "low",
        "0": "info"
    }
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Обходим массив сайтов в отчёте
        for site_entry in data.get("site", []):
            host = site_entry.get("@host", "N/A")
            port = site_entry.get("@port", "")
            full_host = f"{host}:{port}" if port else host
            # Обходим алерты для этого сайта
            for alert in site_entry.get("alerts", []):
                risk_code = alert.get("riskcode", "0")
                severity = zap_severity_mapping.get(risk_code, "info")
                # Увеличиваем счётчик
                severity_counter[severity] += 1
                cwe_id = alert.get("cweid")
                cwe_list = [f"cwe-{cwe_id}"] if cwe_id and cwe_id != "-1" else ["No-CWE"]
                vulnerabilities_details.append({
                    "id": f"zap-{alert.get('pluginid', 'unknown')}",
                    "host": full_host,
                    "url": site_entry.get("@name", "N/A"),
                    "severity": severity.upper(),
                    "cve": "No-CVE",  # ZAP по умолчанию не маппит на CVE, только на CWE
                    "cwe": cwe_list,
                    "timestamp": data.get("@generated", "N/A")
                })
    except Exception as e:
        print(f"[!] Ошибка парсинга файла ZAP '{file_path}': {e}")
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

        # Определяем тип файла на основе его структуры
        try:
            with open(file_path, "r", encoding="utf-8") as test_f:
                # Читаем самое начало файла для быстрой проверки
                start_content = test_f.read(100)
            if "@programName" in start_content or '"site"' in start_content:
                print(f" Обнаружен формат OWASP ZAP. Анализируем: {file_path}")
                stats, details = analyze_zap(file_path)
            else:
                print(f" Обнаружен формат Nuclei. Анализируем: {file_path}")
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

        except Exception as e:
            print(f"[!] Не удалось определить тип файла '{file_path}': {e}")
            
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
            "total_vulnerabilities": total_vulns,
            "counts": dict(total_stats)
        },
        "vulnerabilities": all_vulnerabilities
    }

    try:
        with open(artifact_file, "w", encoding="utf-8") as art_f:
            json.dump(artifact_data, art_f, indent=4, ensure_ascii=False)
        print(f"\n Объединенный артефакт успешно сохранен в: {artifact_file}")
    except Exception as e:
        print(f" Ошибка при сохранении файла артефакта: {e}")
        
    # Блокировка сборки если найдено хотя бы одно CRITICAL или HIGH
    fail_threshold_triggered = total_stats["critical"] > 0 or total_stats["high"] > 0

    if fail_threshold_triggered:
        print("\n СБОРКА ЗАБЛОКИРОВАНА: Обнаружены критические уязвимости (CRITICAL/HIGH)!")
        sys.exit(1)
    else:
        print("\n СБОРКА РАЗРЕШЕНА: Критических угроз не обнаружено.")
        sys.exit(0)

if __name__ == "__main__":
    main()

