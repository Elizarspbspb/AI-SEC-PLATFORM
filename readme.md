# 1. Качаем и проверяем Ollama: 
```
ollama run ALIENTELLIGENCE/cybersecuritythreatanalysisv2
...
ollama list
```
Должно быть примерно:
```
NAME
----------------------------------------------
ALIENTELLIGENCE/cybersecuritythreatanalysisv2
```
Проверяем API Ollama: 
```
curl http://localhost:11434/api/tags
```
Ответ:
```
{
 "models":[
   {
    "name":"ALIENTELLIGENCE/cybersecuritythreatanalysisv2"
   }
 ]
}
```
# 2. Устанавливаем зависимости:
```
python3 -m venv venv

source venv/bin/activate

pip install ollama
pip install langchain
pip install langgraph
```
-------------------------------
# 3. agents
Директория с агентами в системе машинного обучения
## 3.1 Первый тестовый файл агента
agents/test_security_agent.py

## 3.2 Агент анализа отобранных логов
agents/logs_security_agent.py

## 3.3 Агент анализа результатов работы правил Semgrep
agents/code_security_agent.py

Добавляем пустые файлы:
```
touch agents/__init__.py
touch tools/__init__.py
```
Запускать нужно из корня проекта:
```
cd AI-Security-Platform
python -m agents.code_security_agent
```

-------------------------------

# 4. tools
Директория с инструментами для подготовки данных агентам. 

## 4.1 Фильтрация логов по определенным событиям
log_analyzer.py

## 4.2 Функция semgrep 
semgrep_tool.py.py

Какие инструменты потом добавить?
Проверка зависимостей:
pip-audit
npm audit
trivy fs

Глубокий анализ:
CodeQL

Git history:
git log
git diff

-------------------------------

# 5. logs
Директория отфильтрованных логов по подозрительным признакам. 
filtered_events_syslog.json - итоговый набор подозрительных syslog событий; является источником данных для агента - agents/logs_security_agent.py

-------------------------------

# 6.raw_logs
Сырые логи системы. В дальнейшем будут уничтожены.

-------------------------------

# 7. memory
Директория памяти контекста для агента 

-------------------------------

# 8. reports
Директория отчетов от агентов


