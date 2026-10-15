# AI Security Skills

Локальный набор skills и вспомогательных инструментов для аудита PHP-модулей Bitrix перед отправкой в Marketplace. Скилы движок-агностичны — это обычные skill-определения (`SKILL.md`) плюс детерминированные Python-скрипты, поэтому запускаются в любом совместимом agent-CLI. Проект фокусируется на воспроизводимом security-flow: сырой аудит модуля, BUS-aware пересмотр severity, накопительный журнал уязвимостей и ручная разметка мнения разработчика.

## Что внутри

```text
skills/
  bitrix-security/
    scan/                  # глубокий security-аудит одного Bitrix-модуля
      scripts/recon.py     # детерминированный recon-проход (карта attack surface)
      references/          # рубрика severity, чек-лист, таблица Bitrix-паттернов
    journal-review/        # пересмотр severity с учетом Bitrix/BUS-контекста
    journal-update/        # ведение накопительного security-journal.json
    using-marketplace-sec/ # интерактивный оркестратор pre-submission flow (с UI)
    scan-composer/         # headless-оркестратор (одна команда, без UI)

.reports/
  *.json                   # runtime-артефакты проверок, не коммитятся

tools/
  journal_ui_server.py     # локальный UI для просмотра и разметки finding-ов
  vendor/chart.umd.min.js  # vendored Chart.js для UI
```

## Skills

### `scan`

Проводит тщательный аудит одного Bitrix-модуля и сохраняет JSON-отчет в `.reports/<module_code>.json`.

Основные свойства:

- работает по двум фазам: recon attack surface и точечный audit;
- recon-фаза — один детерминированный проход `scripts/recon.py`: карта опасных точек + список целевых файлов, cyrillic-safe (не теряет находки в `windows-1251`);
- ищет Bitrix controllers, AJAX entry points, admin-файлы, handlers, templates и опасные sinks;
- учитывает Bitrix-специфику: `ActionFilter`, `check_bitrix_sessid`, `htmlspecialcharsbx`, `Loader::includeModule`, trusted admin/content-editor boundaries;
- возвращает строгую JSON-структуру с `vulnerabilities`, `summary`, `scannedFiles`, `riskLevel`, `auditedFiles`.

Вызов скила (в любом совместимом agent-CLI):

```text
scan modules/vendor.module
```

Ожидаемый артефакт:

```text
.reports/vendor.module.json
```

### `journal-review`

Пересматривает raw scan severity по политике 1C-Битрикс / boxed Marketplace modules. Это отдельный слой triage: сырой сканер может пометить finding как `high`, но финальный риск должен учитывать источник данных, права пользователя, актуальность `.last_version` и реальную exploitability.

Скрипт:

```bash
python3 skills/bitrix-security/journal-review/scripts/review_journal.py \
  .reports/vendor.module.json \
  --output .reports/vendor.module.reviewed.json
```

Валидация существующего reviewed JSON:

```bash
python3 skills/bitrix-security/journal-review/scripts/review_journal.py \
  --validate-only .reports/vendor.module.reviewed.json
```

Что меняется:

- исходные finding-поля сохраняются;
- `severity` заменяется на reviewed severity;
- добавляется `reviewed` node с rationale, confidence, action, category и version scope;
- добавляется `data.reviewSummary`.

### `journal-update`

Ведет накопительный `security-journal.json` между повторными прогонами. Логика жизненного цикла deterministic и находится в `scripts/update_journal.py`.

Первый запуск:

```bash
python3 skills/bitrix-security/journal-update/scripts/update_journal.py \
  .reports/vendor.module.reviewed.json \
  --module-path modules/vendor.module \
  --output .reports/security-journal.json
```

Повторный запуск с предыдущим журналом:

```bash
python3 skills/bitrix-security/journal-update/scripts/update_journal.py \
  .reports/vendor.module.reviewed.json \
  --previous .reports/security-journal.json \
  --module-path modules/vendor.module \
  --archive-sha256 <sha256> \
  --output .reports/security-journal.json
```

Валидация:

```bash
python3 skills/bitrix-security/journal-update/scripts/update_journal.py \
  --validate-only .reports/security-journal.json
```

Статусы findings:

- `open` - finding актуален и требует решения;
- `false_positive` - разработчик считает finding ложным с пояснением;
- `accepted_risk` - риск принят с пояснением;
- `fixed` - finding больше не воспроизводится;
- `removed` - файл с последней известной уязвимой локацией удален.

Финальный статус из `current_state.status`:

- `ready_for_submission` - нет открытых findings и unresolved dispositions;
- `blocked` - остались открытые `high`;
- `needs_review` - остались открытые low/medium или developer dispositions.

### `using-marketplace-sec`

Оркестратор полного partner-side pre-submission flow:

1. Подготовить предыдущий `security-journal.json`, если он есть.
2. Запустить `scan <module_path>`.
3. Запустить `journal-review` для raw scan.
4. Запустить `journal-update` для накопительного журнала.
5. Провалидировать `security-journal.json`.
6. Запустить локальный UI журнала и проверить, что метрики и карточки показывают актуальный `current_state`, включая сохраненный developer feedback.
7. Сообщить release readiness из `current_state` вместе с URL интерфейса.

Этот skill не содержит собственных audit-heuristics: улучшения аудита живут в `scan`, политика severity - в `journal-review`, lifecycle-состояние - в `journal-update`.

### `scan-composer`

Headless-точка входа того же flow для автоматического запуска: одна команда — путь к модулю, без UI. В отличие от `using-marketplace-sec`, не поднимает журнальный UI и не ведёт накопительный журнал — сырой аудит → BUS-aware review, итог пишется в указанный путь (кросс-ран состояние при таком запуске отслеживает внешний слой). Пути к скриптам и референсам передаются скилу через промпт, поэтому он не привязан к абсолютным путям и работает в любом agent-CLI.

Тоже без собственных эвристик: аудит — в `scan`, политика severity — в `journal-review`.

## End-to-End Flow

Типовой процесс для одного модуля:

```bash
# 1. Сырой аудит
# Как skill: scan modules/vendor.module

# 2. BUS-aware severity review
python3 skills/bitrix-security/journal-review/scripts/review_journal.py \
  .reports/vendor.module.json \
  --output .reports/vendor.module.reviewed.json

# 3. Накопительный journal
python3 skills/bitrix-security/journal-update/scripts/update_journal.py \
  .reports/vendor.module.reviewed.json \
  --previous .reports/security-journal.json \
  --module-path modules/vendor.module \
  --output .reports/security-journal.json

# 4. Валидация финального submission artifact
python3 skills/bitrix-security/journal-update/scripts/update_journal.py \
  --validate-only .reports/security-journal.json

# 5. Обязательный UI для просмотра журнала и feedback
python3 tools/journal_ui_server.py \
  --reviewed .reports/vendor.module.reviewed.json \
  --journal .reports/security-journal.json \
  --host 127.0.0.1 \
  --port 8765
```

Если это первый прогон и предыдущего журнала нет, уберите `--previous .reports/security-journal.json`.
Если порт `8765` занят, используйте следующий свободный порт.

## Локальный UI для журнала

`tools/journal_ui_server.py` поднимает локальную страницу для просмотра reviewed findings и внесения developer feedback:

```bash
python3 tools/journal_ui_server.py \
  --reviewed .reports/vendor.module.reviewed.json \
  --journal .reports/security-journal.json \
  --host 127.0.0.1 \
  --port 8765
```

После запуска откройте:

```text
http://127.0.0.1:8765/
```

UI показывает метрики, тренд, список findings, rationale пересмотра severity и форму "Мнение разработчика". Сохранение обновляет оба файла:

- reviewed scan получает `partner_disposition`;
- cumulative journal обновляет `status`, `latest_vulnerability`, `events` и `current_state`.

## Форматы артефактов

### Raw / reviewed scan

Минимальная структура:

```json
{
  "success": true,
  "requestId": "vendor.module-1780914783",
  "data": {
    "vulnerabilities": [],
    "summary": "Обнаружено ...",
    "scannedFiles": 18,
    "riskLevel": "medium",
    "auditedFiles": []
  }
}
```

Каждая vulnerability должна содержать:

- `file`
- `line`
- `type`
- `severity`
- `description`
- `recommendation`
- `fix`

Reviewed scan дополнительно содержит `reviewed` у каждой vulnerability и `data.reviewSummary`.

### Cumulative journal

`security-journal.json` - основной стабильный артефакт для финальной передачи:

```json
{
  "schema_version": "1.0",
  "module": {},
  "current_state": {},
  "runs": [],
  "findings": []
}
```

Журнал хранит историю запусков, стабильные `journal_finding_id`, fingerprints, статусы, события и последний снимок vulnerability.

## Практические правила

- Не редактировать reviewed severity вручную: запускать `journal-review`.
- Не редактировать lifecycle-счетчики вручную: запускать `journal-update`.
- Не копировать findings из старого отчета вслепую: каждый finding должен быть подтвержден по текущему коду.
- Bitrix-модули часто в `windows-1251`: `recon.py` декодирует байты сам и не теряет такие файлы; при ручном `grep` обязательно используйте `-a`, иначе часть файлов будет пропущена как "binary".
- Финальным submission artifact считается `security-journal.json`; raw и reviewed scan полезны как evidence/debug.

## Лицензия

Проект распространяется под MIT License. См. `LICENSE`.
