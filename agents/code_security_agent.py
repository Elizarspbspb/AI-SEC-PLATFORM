import json
import ollama
from tools.semgrep_tool import run_semgrep

CONFIG_FILE = "./agents/config/code_security_agent_config.json"

def load_config():
    with open(
        CONFIG_FILE,
        encoding="utf-8"
    ) as file:
        return json.load(file)

def analyze_with_llm(findings, model):
    prompt = f"""
Ты Application Security Engineer.
Твоя задача:
проанализировать результаты SAST анализа Semgrep.

Для каждой находки:
1. Проверь является ли это реальной уязвимостью.
2. Определи уровень опасности.
3. Опиши сценарий атаки.
4. Укажи CWE.
5. Предложи исправление.

Не доверяй результатам Semgrep автоматически.
Проверяй контекст.

Результаты Semgrep:
{json.dumps(
    findings,
    indent=2,
    ensure_ascii=False
)}
"""
    response = ollama.chat(
        model=model,
        messages=[
            {
                "role":"user",
                "content":prompt
            }
        ]
    )
    return response["message"]["content"]

def save_report(report, filename):
    with open(filename, "w", encoding="utf-8") as file:
        file.write(report)

def main():
    config = load_config()
    print("[+] Running Semgrep")
    findings = run_semgrep(config["project_path"], config["semgrep_rules"], config["threads"])
    print("[+] Semgrep finished")
    print("[+] Sending results to LLM")
    report = analyze_with_llm(findings, config["model"])
    save_report(report, config["report_file"])
    print("[+] Report saved")

if __name__ == "__main__":
    main()
