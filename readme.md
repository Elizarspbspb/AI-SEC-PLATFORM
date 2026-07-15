# Проверяем Ollama: 
```
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
# Устанавливаем зависимости:
```
python3 -m venv venv

source venv/bin/activate

pip install ollama
pip install langchain
pip install langgraph
```
-------------------------------
# agents
Директория с агентами в СМО
## Первый тестовый файл агента
agents/test_security_agent.py

## Агент анализа отобранных логов
agents/logs_security_agent.py

-------------------------------

# tools
Директория с инструментами для подготовки данных агентам. 

## 

-------------------------------

# logs
Директория отфильтрованных логов по подозрительным признакам. 
filtered_events_syslog.json - итоговый набор подозрительных syslog событий; является источником данных для агента - agents/logs_security_agent.py

-------------------------------

# memory
Директория памяти контекста для агента 
