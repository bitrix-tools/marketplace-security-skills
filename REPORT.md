# Формат итогового журнала `security-journal.json`

Этот документ описывает финальный накопительный журнал безопасности, который можно
сформировать вручную без скилов, если соблюдать структуру и правила ниже.

Финальный журнал - это JSON-файл `security-journal.json`. Он хранит текущее
состояние проверки модуля, историю запусков, стабильные идентификаторы findings,
статусы исправления и последний reviewed-снимок каждой уязвимости.

Raw scan и reviewed scan полезны как evidence/debug-артефакты, но финальным
submission artifact считается именно `security-journal.json`.

## Быстрая проверка валидности

После ручного формирования журнала всегда запустите валидатор:

```bash
python3 skills/bitrix-security/journal-update/scripts/update_journal.py \
  --validate-only security-journal.json
```

Успешный результат:

```text
VALID security journal
```

Валидатор проверяет базовую схему, допустимые статусы, уникальность
`journal_finding_id`, наличие событий и согласованность ключевых счетчиков
`current_state.open_findings` и `current_state.blocking_findings_open`.

Важно: валидатор не доказывает, что finding корректно подтвержден по коду. Он
проверяет только структурную целостность журнала.

## Верхний уровень

Минимальная структура:

```json
{
  "schema_version": "1.0",
  "module": {},
  "current_state": {},
  "runs": [],
  "findings": []
}
```

Все пять ключей обязательны.

| Поле | Тип | Обязательность | Назначение |
|---|---:|---:|---|
| `schema_version` | string | да | Версия схемы. Сейчас допустимо только `"1.0"`. |
| `module` | object | да | Сведения о модуле. Минимально содержит код модуля. |
| `current_state` | object | да | Текущий release-readiness и агрегированные счетчики. |
| `runs` | array | да | История прогонов/пересборок журнала. |
| `findings` | array | да | Накопительный список всех когда-либо обнаруженных findings. |

## `module`

Рекомендуемая структура:

```json
{
  "code": "vendor.module"
}
```

| Поле | Тип | Обязательность | Назначение |
|---|---:|---:|---|
| `code` | string | рекомендуется | Код Bitrix-модуля. Обычно `vendor.module`. |

Можно добавлять дополнительные поля, например `name`, `version`, `vendor`, если
это удобно команде. Текущий валидатор требует только, чтобы `module` был объектом.

## `current_state`

Пример:

```json
{
  "status": "blocked",
  "last_run_id": "vendor.module-1780914783",
  "archive_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "open_findings": 2,
  "blocking_findings_open": 1,
  "false_positive_findings": 0,
  "accepted_risk_findings": 0,
  "fixed_findings": 3,
  "removed_findings": 1,
  "total_findings": 6
}
```

| Поле | Тип | Правило |
|---|---:|---|
| `status` | string | Итоговый статус: `ready_for_submission`, `blocked` или `needs_review`. |
| `last_run_id` | string/null | `run_id` последнего элемента из `runs`. |
| `archive_sha256` | string/null | SHA-256 финального архива модуля, если известен. |
| `open_findings` | number | Количество findings со статусом `open`. |
| `blocking_findings_open` | number | Количество `open` findings с severity `high`. |
| `false_positive_findings` | number | Количество findings со статусом `false_positive`. |
| `accepted_risk_findings` | number | Количество findings со статусом `accepted_risk`. |
| `fixed_findings` | number | Количество findings со статусом `fixed`. |
| `removed_findings` | number | Количество findings со статусом `removed`. |
| `total_findings` | number | Общее количество объектов в `findings`. |

### Расчет `current_state.status`

Используйте ровно такую логику:

1. Если есть хотя бы один открытый `high` finding:
   `status = "blocked"`.
2. Иначе если есть хотя бы один `open`, `false_positive` или `accepted_risk`
   finding: `status = "needs_review"`.
3. Иначе: `status = "ready_for_submission"`.

То есть `ready_for_submission` означает, что все findings имеют только статусы
`fixed` или `removed`.

## `runs`

Каждый элемент `runs` описывает один прогон reviewed scan и обновление
накопительного журнала.

Пример:

```json
{
  "run_id": "vendor.module-1780914783",
  "created_at": "2026-06-08T10:15:30+00:00",
  "archive_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "scanner_request_id": "vendor.module-1780914783",
  "input_summary": "Обнаружено 2 потенциальные уязвимости",
  "summary": {
    "current_scan_findings": 2,
    "severity_counts": {
      "high": 1,
      "medium": 1
    },
    "new_findings": 2,
    "still_open_findings": 0,
    "reopened_findings": 0,
    "resolved_since_previous_run": 0
  }
}
```

| Поле | Тип | Обязательность | Назначение |
|---|---:|---:|---|
| `run_id` | string | рекомендуется | Уникальный ID прогона. Обычно равен `requestId` reviewed scan. |
| `created_at` | string | рекомендуется | ISO-8601 timestamp в UTC или с timezone offset. |
| `archive_sha256` | string/null | рекомендуется | SHA-256 архива, проверенного в этом прогоне. |
| `scanner_request_id` | string/null | рекомендуется | Исходный `requestId` scan/reviewed scan. |
| `input_summary` | string/null | рекомендуется | Краткая сводка из reviewed scan. |
| `summary` | object | рекомендуется | Счетчики по этому прогону. |

### `runs[].summary`

| Поле | Тип | Значение |
|---|---:|---|
| `current_scan_findings` | number | Сколько vulnerabilities было в текущем reviewed scan. |
| `severity_counts` | object | Количество текущих scan findings по reviewed severity. |
| `new_findings` | number | Сколько новых fingerprints появилось в этом прогоне. |
| `still_open_findings` | number | Сколько ранее известных findings снова найдено и не было resolved. |
| `reopened_findings` | number | Сколько resolved findings снова появилось. |
| `resolved_since_previous_run` | number | Сколько ранее открытых findings исчезло из текущего scan. |

`runs` не является строгой частью текущей машинной валидации, но используется UI
для тренда и человеком для аудита истории. Не удаляйте старые runs.

## `findings`

Каждый объект в `findings` - накопительная карточка одного стабильного finding.

Минимально валидируемые поля:

```json
{
  "journal_finding_id": "JF-00001",
  "fingerprint": "e628c7e0f84bc7c8cfdabf52a34b91e3",
  "type": "Cross-Site Scripting",
  "severity": "medium",
  "status": "open",
  "events": [
    {
      "run_id": "vendor.module-1780914783",
      "event": "detected",
      "at": "2026-06-08T10:15:30+00:00"
    }
  ]
}
```

Рекомендуемая полная структура:

```json
{
  "journal_finding_id": "JF-00001",
  "fingerprint": "e628c7e0f84bc7c8cfdabf52a34b91e3",
  "type": "Cross-Site Scripting",
  "severity": "medium",
  "status": "open",
  "first_seen_run_id": "vendor.module-1780914783",
  "last_seen_run_id": "vendor.module-1780914783",
  "resolved_run_id": null,
  "original_location": {
    "file": "install/components/vendor/item/templates/.default/template.php",
    "line": "42"
  },
  "current_location": {
    "file": "install/components/vendor/item/templates/.default/template.php",
    "line": "42"
  },
  "latest_vulnerability": {
    "file": "install/components/vendor/item/templates/.default/template.php",
    "line": 42,
    "type": "Cross-Site Scripting",
    "severity": "medium",
    "description": "Параметр запроса выводится в HTML без экранирования.",
    "recommendation": "Экранировать вывод через htmlspecialcharsbx.",
    "fix": "Заменить прямой echo на htmlspecialcharsbx($value).",
    "reviewed": {
      "oldSeverity": "high",
      "newSeverity": "medium",
      "changed": true,
      "category": "public-reflected-xss",
      "versionScope": "current",
      "version": "current",
      "currentVersionRelevance": "present-in-current-scan",
      "action": "fix",
      "confidence": "high",
      "rationale": "Reflected XSS значим, но не является high без доказанной цепочки к более сильному impact."
    }
  },
  "events": [
    {
      "run_id": "vendor.module-1780914783",
      "event": "detected",
      "at": "2026-06-08T10:15:30+00:00",
      "location": {
        "file": "install/components/vendor/item/templates/.default/template.php",
        "line": "42"
      },
      "status": "open"
    }
  ]
}
```

### Поля finding

| Поле | Тип | Обязательность | Правило |
|---|---:|---:|---|
| `journal_finding_id` | string | да | Уникальный ID вида `JF-00001`, `JF-00002`, ... |
| `fingerprint` | string | да | Стабильный hash finding. См. раздел про fingerprint. |
| `type` | string | да | Тип уязвимости из reviewed scan. |
| `severity` | string | да | Reviewed severity в нижнем регистре. |
| `status` | string | да | Один из допустимых статусов finding. |
| `first_seen_run_id` | string | рекомендуется | Первый run, где finding был обнаружен. |
| `last_seen_run_id` | string | рекомендуется | Последний run, где finding присутствовал. |
| `resolved_run_id` | string/null | рекомендуется | Run, где finding перешел в `fixed` или `removed`. |
| `original_location` | object | рекомендуется | Первая известная локация. |
| `current_location` | object/null | рекомендуется | Текущая локация или `null` для resolved finding. |
| `latest_vulnerability` | object | рекомендуется | Последний reviewed-снимок vulnerability. |
| `resolution` | object | для resolved | Причина перехода в `fixed` или `removed`. |
| `events` | array | да | Непустая история событий finding. |

### Допустимые `severity`

Допустимые значения (ровно три — см. `severity-rubric.md`):

- `high`
- `medium`
- `low`

Для финального журнала используйте reviewed severity, а не raw severity
сканера. Severity влияет на `blocking_findings_open`: только открытые
`high` блокируют submission.

### Допустимые `status`

| Статус | Значение |
|---|---|
| `open` | Finding актуален и требует исправления или решения. |
| `false_positive` | Разработчик считает finding ложным с пояснением. |
| `accepted_risk` | Разработчик принимает риск с пояснением. |
| `fixed` | Finding больше не воспроизводится в текущем reviewed scan. |
| `removed` | Последний известный уязвимый файл отсутствует в текущем дереве модуля. |

`false_positive` и `accepted_risk` не считаются open findings, но переводят
`current_state.status` в `needs_review`.

## `latest_vulnerability`

`latest_vulnerability` должен повторять объект vulnerability из reviewed scan.
Минимально ожидаемые поля:

```json
{
  "file": "path/to/file.php",
  "line": 42,
  "type": "Cross-Site Scripting",
  "severity": "medium",
  "description": "Описание проблемы.",
  "recommendation": "Как исправить.",
  "fix": "Конкретный патч или действие.",
  "reviewed": {
    "oldSeverity": "high",
    "newSeverity": "medium",
    "changed": true,
    "category": "public-reflected-xss",
    "versionScope": "current",
    "version": "current",
    "currentVersionRelevance": "present-in-current-scan",
    "action": "fix",
    "confidence": "high",
    "rationale": "Причина пересмотра severity."
  }
}
```

### `reviewed`

Если журнал формируется вручную без `journal-review`, сохраняйте такую же
структуру `reviewed`, чтобы человек и UI понимали, почему severity именно такая.

| Поле | Тип | Значение |
|---|---:|---|
| `oldSeverity` | string | Severity из raw scan. |
| `newSeverity` | string | Reviewed severity, совпадает с `latest_vulnerability.severity`. |
| `changed` | boolean | `true`, если severity изменилась. |
| `category` | string | Категория triage, например `public-reflected-xss`. |
| `versionScope` | string | `current` или `historical-update`. |
| `version` | string | `.last_version`, номер update package или `current`. |
| `currentVersionRelevance` | string | Например `present-in-current-scan` или `historical-update-package`. |
| `action` | string | Рекомендуемое действие: `fix`, `parameterize-query`, `harden-output-escaping`, ... |
| `confidence` | string | `high`, `medium` или `low`. |
| `rationale` | string | Короткое объяснение решения. |

Правило: `latest_vulnerability.severity`, `findings[].severity` и
`reviewed.newSeverity` должны описывать одно и то же reviewed severity.

## Developer feedback: `partner_disposition`

Если разработчик размечает finding как ложное срабатывание или принятый риск,
feedback хранится внутри `latest_vulnerability.partner_disposition`.

Пример false positive:

```json
{
  "status": "false_positive",
  "note": "Параметр проходит whitelist по числовому ID до использования в SQL.",
  "author": "dev@example.com",
  "updated_at": "2026-06-08T11:00:00+00:00"
}
```

Пример accepted risk:

```json
{
  "status": "accepted_risk",
  "note": "Остается только для закрытого админского сценария; исправление запланировано в следующем релизе.",
  "author": "dev@example.com",
  "updated_at": "2026-06-08T11:05:00+00:00"
}
```

Правила:

- `partner_disposition.status` может быть только `false_positive` или
  `accepted_risk`.
- Если finding снова должен стать обычным открытым finding, удалите
  `partner_disposition` и поставьте `findings[].status = "open"`.
- При изменении developer feedback добавьте событие
  `partner_disposition_updated` в `events`.
- `findings[].status` должен совпадать с `partner_disposition.status`, если
  disposition присутствует.

## `events`

`events` - непустая история изменений finding.

Типовые события:

| `event` | Когда использовать |
|---|---|
| `detected` | Finding найден впервые. |
| `detected_again` | Finding снова найден в новом прогоне и ранее не был resolved. |
| `reopened` | Finding был `fixed`/`removed`, но снова появился. |
| `resolved` | Finding исчез из reviewed scan и стал `fixed` или `removed`. |
| `partner_disposition_updated` | Разработчик изменил статус на `false_positive`, `accepted_risk` или вернул `open`. |

Примеры:

```json
{
  "run_id": "vendor.module-1780914783",
  "event": "detected",
  "at": "2026-06-08T10:15:30+00:00",
  "location": {
    "file": "path/to/file.php",
    "line": "42"
  },
  "status": "open"
}
```

```json
{
  "run_id": "vendor.module-1780915000",
  "event": "resolved",
  "at": "2026-06-08T11:20:00+00:00",
  "status": "fixed"
}
```

```json
{
  "run_id": "vendor.module-1780915000",
  "event": "partner_disposition_updated",
  "at": "2026-06-08T11:25:00+00:00",
  "status": "accepted_risk",
  "note": "Исправление перенесено на следующий релиз.",
  "author": "dev@example.com"
}
```

## Fingerprint

Fingerprint связывает один и тот же finding между повторными прогонами. Он
вычисляется как SHA-256 от нормализованных полей и обрезается до первых 32 hex
символов.

Материал для hash:

1. `type`, приведенный к нижнему регистру и сжатый по пробелам.
2. reviewed `severity`, приведенная к нижнему регистру.
3. `file`, где `\` заменены на `/`, начальные `./` удалены.
4. `line`, приведенный к строке и сжатый по пробелам.
5. `description`, приведенный к нижнему регистру и сжатый по пробелам.

Поля соединяются через `\n`.

Эквивалентная Python-функция:

```python
import hashlib
import re


def normalize_text(value):
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def normalize_file(value):
    text = str(value or "").replace("\\", "/").strip()
    return re.sub(r"^\./+", "", text)


def vulnerability_fingerprint(vuln):
    parts = [
        normalize_text(vuln.get("type")),
        normalize_text(vuln.get("severity")),
        normalize_file(vuln.get("file")),
        normalize_text(vuln.get("line")),
        normalize_text(vuln.get("description")),
    ]
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:32]
```

Практический вывод: если изменить описание, line, file, type или reviewed
severity, fingerprint изменится, и журнал будет считать finding новым.

## Lifecycle findings

### Первый прогон

Для каждого finding из текущего reviewed scan:

- создать новый `journal_finding_id`;
- вычислить `fingerprint`;
- поставить `status = "open"`, если нет `partner_disposition`;
- если есть `partner_disposition.status = "false_positive"` или
  `"accepted_risk"`, использовать этот статус;
- заполнить `first_seen_run_id`, `last_seen_run_id`, `original_location`,
  `current_location`, `latest_vulnerability`;
- добавить event `detected`.

### Повторный прогон

Для каждого finding из нового reviewed scan:

- если fingerprint уже есть, сохранить прежний `journal_finding_id`;
- обновить `severity`, `type`, `last_seen_run_id`, `current_location`,
  `latest_vulnerability`;
- если finding был `fixed` или `removed`, поставить `status = "open"` и добавить
  event `reopened`;
- иначе добавить event `detected_again`;
- если раньше был `false_positive` или `accepted_risk`, а новый scan не принес
  другой `partner_disposition`, сохранить прежний developer disposition.

Для ранее открытых findings, которых нет в новом reviewed scan:

- поставить `status = "removed"`, если последний известный файл отсутствует в
  текущем дереве модуля;
- иначе поставить `status = "fixed"`;
- заполнить `resolved_run_id`;
- поставить `current_location = null`;
- добавить `resolution`;
- добавить event `resolved`.

Не удаляйте старые findings. История должна оставаться накопительной.

## `resolution`

Для `fixed`:

```json
{
  "type": "not_reproduced_after_rescan",
  "resolved_in_run": "vendor.module-1780915000",
  "reason": "The reviewed scan no longer reports a matching finding for the current archive."
}
```

Для `removed`:

```json
{
  "type": "file_removed",
  "resolved_in_run": "vendor.module-1780915000",
  "reason": "Last known vulnerable file is absent in the current module tree."
}
```

## Полный пример журнала

```json
{
  "schema_version": "1.0",
  "module": {
    "code": "vendor.module"
  },
  "current_state": {
    "status": "needs_review",
    "last_run_id": "vendor.module-1780915000",
    "archive_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "open_findings": 1,
    "blocking_findings_open": 0,
    "false_positive_findings": 1,
    "accepted_risk_findings": 0,
    "fixed_findings": 1,
    "removed_findings": 0,
    "total_findings": 3
  },
  "runs": [
    {
      "run_id": "vendor.module-1780914783",
      "created_at": "2026-06-08T10:15:30+00:00",
      "archive_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "scanner_request_id": "vendor.module-1780914783",
      "input_summary": "Обнаружено 3 потенциальные уязвимости",
      "summary": {
        "current_scan_findings": 3,
        "severity_counts": {
          "medium": 2,
          "low": 1
        },
        "new_findings": 3,
        "still_open_findings": 0,
        "reopened_findings": 0,
        "resolved_since_previous_run": 0
      }
    },
    {
      "run_id": "vendor.module-1780915000",
      "created_at": "2026-06-08T11:20:00+00:00",
      "archive_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "scanner_request_id": "vendor.module-1780915000",
      "input_summary": "Обнаружено 2 потенциальные уязвимости",
      "summary": {
        "current_scan_findings": 2,
        "severity_counts": {
          "medium": 1,
          "low": 1
        },
        "new_findings": 0,
        "still_open_findings": 2,
        "reopened_findings": 0,
        "resolved_since_previous_run": 1
      }
    }
  ],
  "findings": [
    {
      "journal_finding_id": "JF-00001",
      "fingerprint": "11111111111111111111111111111111",
      "type": "Cross-Site Scripting",
      "severity": "medium",
      "status": "open",
      "first_seen_run_id": "vendor.module-1780914783",
      "last_seen_run_id": "vendor.module-1780915000",
      "resolved_run_id": null,
      "original_location": {
        "file": "install/components/vendor/search/templates/.default/template.php",
        "line": "42"
      },
      "current_location": {
        "file": "install/components/vendor/search/templates/.default/template.php",
        "line": "42"
      },
      "latest_vulnerability": {
        "file": "install/components/vendor/search/templates/.default/template.php",
        "line": 42,
        "type": "Cross-Site Scripting",
        "severity": "medium",
        "description": "Параметр запроса выводится в HTML без экранирования.",
        "recommendation": "Экранировать пользовательский ввод перед выводом.",
        "fix": "Использовать htmlspecialcharsbx($query).",
        "reviewed": {
          "oldSeverity": "high",
          "newSeverity": "medium",
          "changed": true,
          "category": "public-reflected-xss",
          "versionScope": "current",
          "version": "current",
          "currentVersionRelevance": "present-in-current-scan",
          "action": "fix",
          "confidence": "high",
          "rationale": "Reflected XSS значим, но не является high без доказанного усиления impact."
        }
      },
      "events": [
        {
          "run_id": "vendor.module-1780914783",
          "event": "detected",
          "at": "2026-06-08T10:15:30+00:00",
          "location": {
            "file": "install/components/vendor/search/templates/.default/template.php",
            "line": "42"
          },
          "status": "open"
        },
        {
          "run_id": "vendor.module-1780915000",
          "event": "detected_again",
          "at": "2026-06-08T11:20:00+00:00",
          "location": {
            "file": "install/components/vendor/search/templates/.default/template.php",
            "line": "42"
          },
          "status": "open"
        }
      ]
    },
    {
      "journal_finding_id": "JF-00002",
      "fingerprint": "22222222222222222222222222222222",
      "type": "SQL Injection",
      "severity": "medium",
      "status": "false_positive",
      "first_seen_run_id": "vendor.module-1780914783",
      "last_seen_run_id": "vendor.module-1780915000",
      "resolved_run_id": null,
      "original_location": {
        "file": "lib/repository.php",
        "line": "88"
      },
      "current_location": {
        "file": "lib/repository.php",
        "line": "88"
      },
      "latest_vulnerability": {
        "file": "lib/repository.php",
        "line": 88,
        "type": "SQL Injection",
        "severity": "medium",
        "description": "Значение ID используется в SQL-запросе.",
        "recommendation": "Параметризовать запрос или привести ID к integer.",
        "fix": "Использовать (int)$id либо query binding.",
        "reviewed": {
          "oldSeverity": "high",
          "newSeverity": "medium",
          "changed": true,
          "category": "sql-injection",
          "versionScope": "current",
          "version": "current",
          "currentVersionRelevance": "present-in-current-scan",
          "action": "parameterize-query",
          "confidence": "medium",
          "rationale": "SQL injection по BUS triage обычно medium, если journal text не доказывает более высокий impact."
        },
        "partner_disposition": {
          "status": "false_positive",
          "note": "ID приводится к integer в вызывающем методе до попадания сюда.",
          "author": "dev@example.com",
          "updated_at": "2026-06-08T11:25:00+00:00"
        }
      },
      "events": [
        {
          "run_id": "vendor.module-1780914783",
          "event": "detected",
          "at": "2026-06-08T10:15:30+00:00",
          "location": {
            "file": "lib/repository.php",
            "line": "88"
          },
          "status": "open"
        },
        {
          "run_id": "vendor.module-1780915000",
          "event": "partner_disposition_updated",
          "at": "2026-06-08T11:25:00+00:00",
          "status": "false_positive",
          "note": "ID приводится к integer в вызывающем методе до попадания сюда.",
          "author": "dev@example.com"
        }
      ]
    },
    {
      "journal_finding_id": "JF-00003",
      "fingerprint": "33333333333333333333333333333333",
      "type": "Hardcoded Secret",
      "severity": "low",
      "status": "fixed",
      "first_seen_run_id": "vendor.module-1780914783",
      "last_seen_run_id": "vendor.module-1780914783",
      "resolved_run_id": "vendor.module-1780915000",
      "original_location": {
        "file": "install/index.php",
        "line": "12"
      },
      "current_location": null,
      "latest_vulnerability": {
        "file": "install/index.php",
        "line": 12,
        "type": "Hardcoded Secret",
        "severity": "low",
        "description": "В коде присутствует демонстрационный токен.",
        "recommendation": "Удалить токен из исходного кода.",
        "fix": "Перенести значение в настройки модуля.",
        "reviewed": {
          "oldSeverity": "low",
          "newSeverity": "low",
          "changed": false,
          "category": "hardcoded-default-token-hygiene",
          "versionScope": "current",
          "version": "current",
          "currentVersionRelevance": "present-in-current-scan",
          "action": "remove-default-secret",
          "confidence": "medium",
          "rationale": "Impact зависит от реальности и прав токена."
        }
      },
      "resolution": {
        "type": "not_reproduced_after_rescan",
        "resolved_in_run": "vendor.module-1780915000",
        "reason": "The reviewed scan no longer reports a matching finding for the current archive."
      },
      "events": [
        {
          "run_id": "vendor.module-1780914783",
          "event": "detected",
          "at": "2026-06-08T10:15:30+00:00",
          "location": {
            "file": "install/index.php",
            "line": "12"
          },
          "status": "open"
        },
        {
          "run_id": "vendor.module-1780915000",
          "event": "resolved",
          "at": "2026-06-08T11:20:00+00:00",
          "status": "fixed"
        }
      ]
    }
  ]
}
```

Пример выше структурно валиден, но fingerprints намеренно показаны как
условные `111...`, `222...`, `333...`. В реальном журнале вычисляйте их по
алгоритму из раздела `Fingerprint`.

## Чеклист ручного формирования

1. Создайте верхний объект с `schema_version`, `module`, `current_state`,
   `runs`, `findings`.
2. Для каждого reviewed finding вычислите fingerprint.
3. Для каждого нового fingerprint назначьте следующий `journal_finding_id`.
4. Скопируйте reviewed vulnerability в `latest_vulnerability`.
5. Заполните `original_location`, `current_location`, `first_seen_run_id`,
   `last_seen_run_id`.
6. Выставьте `status`: `open`, `false_positive`, `accepted_risk`, `fixed` или
   `removed`.
7. Добавьте хотя бы одно событие в `events`.
8. Обновите `runs`.
9. Пересчитайте все счетчики в `current_state`.
10. Рассчитайте `current_state.status`.
11. Запустите `--validate-only`.

## Типичные ошибки

- Используют raw severity вместо reviewed severity.
- Меняют `journal_finding_id` при повторном появлении того же fingerprint.
- Удаляют старые resolved findings из `findings`.
- Забывают пересчитать `current_state.open_findings`.
- Оставляют `blocking_findings_open = 0`, хотя есть open `high`.
- Ставят `false_positive` в `latest_vulnerability.partner_disposition`, но
  забывают поменять `findings[].status`.
- Не добавляют `events` или оставляют пустой массив.
- Меняют `description` между прогонами без необходимости и получают новый
  fingerprint.
- Считают `ready_for_submission` допустимым при `false_positive` или
  `accepted_risk`; по текущей логике это `needs_review`.

## Машинное создание вместо ручного

Если reviewed scan уже есть, надежнее обновить журнал скриптом:

```bash
python3 skills/bitrix-security/journal-update/scripts/update_journal.py \
  .reports/vendor.module.reviewed.json \
  --previous .reports/security-journal.json \
  --module-path modules/vendor.module \
  --archive-sha256 <sha256> \
  --output .reports/security-journal.json
```

Для первого прогона уберите `--previous`.

После этого:

```bash
python3 skills/bitrix-security/journal-update/scripts/update_journal.py \
  --validate-only .reports/security-journal.json
```
