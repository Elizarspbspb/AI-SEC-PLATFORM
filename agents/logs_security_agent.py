import json
import ollama

MODEL = "ALIENTELLIGENCE/cybersecuritythreatanalysisv2"
INPUT_FILE = "../logs/filtered_events_syslog.json"
REPORT_FILE = "../reports/log_report.md"

SYSTEM_PROMPT = """
Ты являешься Security Operations Center (SOC) Analyst Agent.
Твоя задача:
Анализировать события безопасности из системных логов.
Для каждого события:
1. Определи является ли оно угрозой.
2. Определи тип атаки.
3. Сопоставь с MITRE ATT&CK техникой.
4. Оцени уровень риска:
   - Low
   - Medium
   - High
   - Critical
5. Опиши:
   - что произошло;
   - возможную причину;
   - возможные действия атакующего;
   - рекомендации защиты.

Не делай вывод только по одному ключевому слову.
Учитывай контекст события.

Формат ответа:
## Event
Описание

## Threat classification
Тип угрозы

## MITRE ATT&CK
Техника

## Risk
Уровень

## Recommendation
Что сделать.
"""

def load_events():
    with open(
        INPUT_FILE,
        encoding="utf-8"
    ) as file:
        return json.load(file)

def analyze_events(events):
    prompt = SYSTEM_PROMPT + """
Ниже события из системы:
""" + json.dumps(
        events,
        indent=4,
        ensure_ascii=False
    )
    response = ollama.chat(
        model=MODEL,
        messages=[
            {
                "role":"user",
                "content":prompt
            }
        ]
    )
    return response["message"]["content"]

def save_report(report):
    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        file.write(report)

if __name__ == "__main__":
    events = load_events()
    if len(events) == 0:
        print("[+] No security events")
        exit()
    report = analyze_events(events)
    save_report(report)
    print("[+] Analysis completed")
    print("[+] Report:",REPORT_FILE)
