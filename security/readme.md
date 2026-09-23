# Основные понятия GitHub Actions
1. **Workflow** — весь описанный в YAML процесс CI/CD. Например, `Security Pipeline`.
2. **Job** — отдельная задача внутри Workflow. Например, `security` или `gate`.
3. **Step** — отдельное действие внутри Job. Например, `Checkout`, `Trivy SCA`, `Security gate`.
4. **Jobs** могут выполняться параллельно, если между ними нет зависимости.
5. **Steps** внутри одной Job выполняются последовательно, один за другим.
6. **`needs`** — конструкция, которая задаёт зависимость между Jobs. Например, `needs: security` начнёт выполняться только после завершения `security`.
7. **Stage** — в GitHub Actions отдельного объекта Stage нет. Мы используем это слово только для обозначения логического этапа нашего pipeline, например SCA, SAST, Secret Detection.
8. **Runner** — машина, на которой GitHub выполняет Job. В нашем случае используется `ubuntu-latest`.
9. **`exit 0`** — программа завершилась успешно. GitHub Actions считает Step успешным.
10. **`exit 1`** — программа завершилась с ошибкой. GitHub Actions считает Step неуспешным, Job становится красной.
11. **Pipeline** — в нашем проекте это весь процесс проверки кода: запуск сканеров, обработка результатов и принятие решения о прохождении проверки.
12. **Artifact** — файл, который Job сохраняет после выполнения и который можно передать другой Job или скачать из GitHub Actions. Например, результат сканирования `trivy.json`.
13. **Required status check** — обязательная проверка GitHub Actions для защищённой ветки. Если проверка не пройдена, Merge Pull Request запрещается.
14. **Pull Request** — запрос на внесение изменений из одной ветки в другую, например из `feature/test` в `main`.
15. **Push** — отправка коммитов из локального репозитория на GitHub. Ошибка Pipeline не отменяет Push.
16. **Защита ветки `main`** — настройка GitHub, при которой для Merge могут быть обязательны определённые проверки, например `security`.
17. В нашем проекте логика будет такой:

---

Pipeline - /AI-SEC-PLATFORM/.github/workflows/security.yml
# 0. Git Push -> Триггер пайплайна -> GitHub actions
В корне проекта создать файл: .github/workflows/security.yml
```
name: Security Pipeline
on:
  push:
    # Проверяем пуши во все ветки
    branches: [ "**" ]
  pull_request:
    # Также проверять PR перед слиянием
    types: [opened, synchronize, reopened]
jobs:
  TestEcho:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Скачиваем историю, чтобы Git мог сравнить коммиты
      - name: Test GitHub Actions
        run: |
          echo "Security pipeline started"
          echo "Repository: ${{ github.repository }}"
          echo "Commit: ${{ github.sha }}"
```
Каждый раз, когда кто-то делает git push в репозиторий, запускается этот workflow. GitHub официально поддерживает push как триггер workflow. Можно также ограничивать его конкретными ветками.
```
git add .github/workflows/security.yml
git commit -m "add GitHub Actions security pipeline"
git push
```
После push зайти на GitHub → свой репозиторий → Actions.

# 1. Этап 1: Секреты (Secret Detection)
    * Инструмент: Trufflehog и Gitleaks.
    * Зачем: Проверяет, не забыл ли разработчик закоммитить в код пароли, API-ключи или приватные токены. 
    Пайплайн должен падать, если секреты найдены.
## 1.1 TruffleHog
Для GitHub Actions существует готовый action: `trufflesecurity/trufflehog`
Добавьте в security.yml:
```
...
    steps:
    ...
      - name: TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          # event.before содержит хэш до пуша. Мы проверяем изменения от него до текущего HEAD.
          base: ${{ github.event.before }}
          head: HEAD
          extra_args: --results=verified,unknown
```
## 1.2 Gitleaks
У Gitleaks есть официальный GitHub Action: gitleaks/gitleaks-action
Для личного GitHub-аккаунта лицензия Gitleaks для action не требуется:
```
    steps:
    ...
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v3
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_CONFIG: ${{ github.workspace }}/.gitleaks.toml
```
`GITLEAKS_CONFIG` — официальный способ явно указать Action, какой конфигурационный файл использовать.
В директории проекта создать файл - `.gitleaks.toml`
```
title = "AI-SEC-PLATFORM Gitleaks config"

[extend]
useDefault = true

[allowlist]
description = "Ignore raw_logs"
paths = [
   '''raw_logs/''',
   '''syslog\.txt'''
]

```
Прежде чем снова пушить, сделать проверку локально. Если Gitleaks установлен локально:
```
gitleaks detect --config .gitleaks.toml --source . -v
или
gitleaks detect --config .gitleaks.toml --source . --no-git -v
```
Если вы запускаете проверку через команду `gitleaks detect` (которая сканирует файлы в текущей рабочей директории), этот конфиг сработает сразу. Однако, если вы используете `gitleaks protect` или проверяете историю коммитов `gitleaks history`, Gitleaks смотрит на git-диффы (изменения). Если файл уже был закоммичен ранее, и вы проверяете старые коммиты, убедитесь, что в тех старых коммитах путь к файлу соответствовал регулярному выражению.

# 2. Этап 2: Анализ сторонних библиотек (SCA — Software Component Analysis)
    * Инструмент: OWASP Dependency-Check и Trivy.
    * Зачем: Проверяет уязвимости в зависимостях приложения (известные CVE в пакетах).

## 2.1 OWASP Dependency-Check
Инструмент проверяет проекты на JavaScript/TypeScript (npm/yarn), Python, C# (.NET), PHP, Go и других языках.
Добавить в пайплайн:
```
- name: Run OWASP Dependency-Check
        # Модуль отключен - false, true - включен
        if: false
        uses: dependency-check/Dependency-Check_Action@main
        id: DependencyCheck
        with:
          project: 'AI-SEC-PLATFORM'
          path: '.'
          # Выходной формат файла
          format: 'SARIF,HTML'
          # --enableRetired - поиск устаревших библиотек JS
          # --failOnCVSS 3 - пайплайн упадет если CVSS >= 3.0
          # --enableHighRiskIndex - высокорискованные методы анализа
          # NVD_API_KEY - ключ качает инфу об уязвимостях
          args: >
            --failOnCVSS 3
            --nvdApiKey ${{ secrets.NVD_API_KEY }}
```
1. Обязательно получите `NVD API Key`.
2. Перейдите на NVD Developer Portal и запросите бесплатный ключ.
3. Добавьте его в свой репозиторий в Settings -> Secrets and variables -> Actions -> New repository secret под именем `NVD_API_KEY`.
* Если у вас Node.js: инструмент будет искать файлы package-lock.json или yarn.lock.
* Если у вас Python: он ищет requirements.txt или poetry.lock.
```
pip freeze > requirements.txt
```
* Если у вас .NET: он проверяет файлы проектов .csproj и packages.config.

## 2.2 Trivy
Для Trivy в GitHub Actions можно использовать официальный action:
```
...
      - name: Trivy SCA
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: "fs"
          scan-ref: "."
          scanners: "vuln"
          format: "json"
          exit-code: "1"
          severity: "CRITICAL,HIGH"
```
* `scan-type: "fs"` - Сканирует всю файловую систему проекта.
* `scanners: "vuln"` - поиск известных уязвимостей. 
* `severity: "CRITICAL,HIGH"` - интересуют Critical и High.

В консоли можно проверить:
```
trivy fs --format json --output trivy_json.json --scanners vuln --severity CRITICAL,HIGH,MEDIUM .
```

# 3. Этап 3: Статический анализ кода (SAST)
    * Инструмент: Semgrep (универсальный, быстрый, мега-популярный) или SonarQube или Svace (от ИСП РАН) или Solar.
    * Зачем: Ищет уязвимости (SQL-инъекции, XSS, небезопасные функции) прямо в исходном коде.

## 3.1 Semgrep    
* Основные правила Semgrep — получать автоматически из официального набора правил.
Не хранить semgrep-rules в GitHub-репозитории.
Чтобы не скачивать огромный набор заново на каждый push, можно использовать GitHub Actions cache.
```
- name: Cache Semgrep rules
      id: semgrep-cache
      uses: actions/cache@v4
      with:
        path: .semgrep-rules
        key: semgrep-rules-v1

    - name: Download Semgrep rules
      if: steps.semgrep-cache.outputs.cache-hit != 'true'
      run: |
        git clone --depth 1 https://github.com/semgrep/semgrep-rules.git .semgrep-rules
```
* Собственные правила — запускать отдельно из security/SAST/semgrep/custom-rules.yml.
Лучше запускать:
```
semgrep scan --config /home/user/workspace/semgrep-rules/python . --json --output semgrep.json
```

# 4. Этап 4: Создание Docker Build и проверка Docker-образа (Container Scanning)
    * Инструмент: Trivy (он отлично сканирует и образы).
    * Зачем: Ищет уязвимости в базовой ОС контейнера перед деплоем.
5. Этап 5: Динамический анализ (DAST) — Опционально для продвинутых
    * Инструмент: OWASP ZAP (в режиме автоматического сканирования API/веба) и Nuclei
    * Зачем: ...
6. Этап 6: Провекра JWT и OAuth 2.0.
    * Инструмент: не определен или свой python код. 
    * Зачем: ...
7. Этап 7: Средства автоматизированных атак на веб-приложение
    * Инструмент:  SQLMap и XSStrike
    * Зачем: ...
8. Этап 8: Формирование JSON файла - vulnerabilities.json
    * Инструмент: готовый python скрипт нормализации.
    * Зачем: Формируем положительный или отрицательный результат - security_gate.py

# 9. Получение отчетов из Github
Скачать и установить GitHub CLI (gh)
```
sudo apt update
sudo apt install gh
```
Как только программа установится, нужно один раз авторизоваться в своем аккаунте GitHub:
```
gh auth login
```
1. Чтобы продолжить:
Нажмите клавишу Enter, так как стрелочка уже указывает на стандартный GitHub.com (если вам нужен обычный GitHub, а не корпоративный сервер компании).
2. Дальше утилита задаст еще 3-4 простых вопроса. Выбирайте следующие варианты:
    * What is your preferred protocol for Git operations? — выберите HTTPS (это проще всего) или SSH (если у вас уже настроены ключи).
    * Authenticate Git with your GitHub credentials? — нажмите Y (Yes), чтобы CLI автоматически подтягивал ваши данные при отправке кода.
    * How would you like to authenticate GitHub CLI? — выберите Login with a web browser (Вход через браузер).
3. Финальный шаг
   После выбора входа через браузер утилита:
   * Выдаст вам 8-значный одноразовый код (например, XXXX-XXXX).
   * Нажмите Enter, чтобы автоматически открылся браузер, либо вручную перейдите по указанной ссылке (обычно ://github.com).
   * Вставьте этот код на странице в браузере и нажмите Authorize github.

Перейдите в терминале в папку с проектом (где находится локальный Git-репозиторий) и запустите:
```
gh run list --limit 10
```
или если репозиторий не скачан:
```
gh run list --repo Elizarspbspb/НАЗВАНИЕ_РЕПОЗИТОРИЯ --limit 10
```
Скачать артефакты последнего запуска:
```
gh run download
```
Интерактивный выбор:
```
gh run download --interactive
```
Скачивание по ID запуска:
```
gh run download 123456789
```
Сохранить в определенную папку: 
```
gh run download -D ./my-artifacts
```
Скачать только конкретный файл по имени: 
```
gh run download --name "name_file"
```
