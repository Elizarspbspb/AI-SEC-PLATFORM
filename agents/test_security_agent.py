import ollama
MODEL = "ALIENTELLIGENCE/cybersecuritythreatanalysisv2"

def analyze(text):
    prompt = f"""
Ты Senior Application Security Engineer.
Проанализируй объект:
{text}
Найди:
1. Уязвимости
2. Возможные атаки
3. CWE
4. MITRE ATT&CK
5. Риск
6. Рекомендации защиты
Ответ структурируй.
"""
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

if __name__ == "__main__":
    result = analyze(
        """
        nginx access log:

        POST /login
        user=admin
        password=test
        """
    )
    print(result)
