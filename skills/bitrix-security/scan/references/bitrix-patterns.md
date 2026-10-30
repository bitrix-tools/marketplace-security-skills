# Bitrix Patterns Reference

Шпаргалка по опасным и безопасным паттернам Bitrix API. Помогает сабагенту не путать «вроде проблема» с «вроде нормально».

## Escaping

| Контекст | ✅ Безопасно | ❌ Опасно |
|---|---|---|
| HTML body | `htmlspecialcharsbx($var)` | `<?= $var ?>` без обёртки |
| HTML attribute | `htmlspecialcharsbx($var)` | `htmlspecialchars($var)` (по умолчанию пропускает `'`) |
| JS context | `\Bitrix\Main\Web\Json::encode($var)`, `CUtil::JSEscape($var)`, `CUtil::PhpToJSObject($arr)` | прямая вставка `<?=$var?>` в `<script>` |
| URL/href | `urlencode($var)` + проверка схемы (на `javascript:`) | прямая вставка в `href="..."` |
| SQL string | placeholders `?` + bind, `(int)$id`, `$DB->ForSql($var)` | конкатенация |

## Controller actions (`\Bitrix\Main\Engine\Controller`)

**Минимальный безопасный configureActions для state-changing:**

```php
public function configureActions()
{
    return [
        'saveXxx' => [
            'prefilters' => [
                new \Bitrix\Main\Engine\ActionFilter\Authentication(),
                new \Bitrix\Main\Engine\ActionFilter\HttpMethod([
                    \Bitrix\Main\Engine\ActionFilter\HttpMethod::METHOD_POST,
                ]),
                new \Bitrix\Main\Engine\ActionFilter\Csrf(),
            ],
        ],
    ];
}
```

Если `'prefilters' => []` или отсутствует `Csrf` — флагируй.

**КРИТИЧНО — `-prefilters` (вычитающий синтаксис).** Bitrix позволяет НЕ добавлять, а **убирать** дефолтный фильтр через ключ `'-prefilters'`:

```php
public function configureActions()
{
    return [
        'createTemplate' => [
            '-prefilters' => [
                \Bitrix\Main\Engine\ActionFilter\Authentication::class,
            ],
        ],
    ];
}
```

Это **опаснее**, чем пустые `prefilters`: по умолчанию `Engine\Controller` навешивает `Authentication` (+ часто `Csrf`) на ВСЕ action-методы. `-prefilters` с `Authentication::class` означает **«сделать этот action доступным анонимно»**. Любой `-prefilters`, убирающий `Authentication`, `Csrf` или `HttpMethod` для state-changing метода — это **high severity** (если убран `Authentication` — потенциально неавторизованный доступ). Ищи grep-ом `'-prefilters'` и `-prefilters` отдельно.

**Дефолты Controller (когда `configureActions` НЕ определён или не покрывает метод).** Если класс наследует `\Bitrix\Main\Engine\Controller` и для action нет записи в `configureActions`, применяются дефолтные prefilters — `Authentication` (+ `Csrf` в современных версиях). Это **безопасно по умолчанию** для проверки личности/CSRF. НО `Authentication` ≠ проверка прав: авторизованный пользователь без админ-прав всё равно проходит фильтр. Поэтому для админских/привилегированных операций по-прежнему нужна явная проверка (`$USER->IsAdmin()` / `GetGroupRight`) внутри метода — иначе это IDOR/privilege-escalation, а не Auth Bypass.

**Внутри action метода — дополнительно:**
- Проверка прав на конкретный ресурс (IDOR): `if (!$this->canEdit($id))`
- Приведение типов: `(int)$params['id']`, `(string)$params['name']`

## AJAX-файлы (legacy формат, не Engine\Controller)

```php
<?php
require($_SERVER['DOCUMENT_ROOT'].'/bitrix/modules/main/include/prolog_before.php');

if (!check_bitrix_sessid()) {
    http_response_code(403);
    die('Forbidden');
}

global $USER;
if (!$USER->IsAuthorized()) {
    http_response_code(401);
    die('Unauthorized');
}

// затем — собственно логика
```

Если в файле есть `$_REQUEST['action']` и **нет** `check_bitrix_sessid()` + `IsAuthorized()` для state-changing action — это уязвимость (severity зависит от того, что меняется).

## Database access

**Безопасно:**
```php
\Bitrix\Main\Application::getConnection()
    ->queryExecute('SELECT * FROM table WHERE ID = ?', [(int)$id]);

\Bitrix\Vote\VoteTable::getList([
    'filter' => ['=ID' => (int)$id],  // ORM-фильтр валидирует ключи
]);

$DB->Query("SELECT * FROM table WHERE ID = " . (int)$id);  // приведение типа
```

**Опасно:**
```php
$DB->Query("SELECT * FROM table WHERE NAME = '" . $_GET['name'] . "'");
$DB->Query("SELECT * FROM table WHERE NAME = '" . $DB->ForSqlLike($_GET['name']) . "'");
// ↑ ForSqlLike — для LIKE, не общая защита; всё равно нужен ForSql
\Bitrix\Vote\VoteTable::getList(['filter' => $_REQUEST['filter']]);  // RAW filter
\Bitrix\Vote\VoteTable::getList(['order' => $_REQUEST['order']]);    // RAW order
```

## File operations

**Безопасный upload:**
```php
$fileId = \CFile::SaveFile($_FILES['upload'], 'module.name');
// CFile делает санитизацию имени и проверяет тип
```

**Опасный upload:**
```php
move_uploaded_file($_FILES['upload']['tmp_name'], '/var/www/' . $_FILES['upload']['name']);
```

## Include / require

**Опасно:**
```php
include $_GET['template'] . '.php';
require_once $componentPath . '/' . $userControlledName;
```

**Безопасно:**
- allowlist разрешённых имён
- `realpath()` + проверка префикса
- использование Bitrix `IncludeTemplateLangFile`, `IncludeComponent` с фиксированными именами

## Bitrix-специфичные функции, на которые обращать внимание

| Функция | Риск |
|---|---|
| `CFile::SaveFile` | Безопасна, но проверь — обрабатывается ли возвращаемое значение |
| `CFile::Delete($id)` | Безопасна по `$id`, опасна если `$id` — путь |
| `IncludeFile($path)` | Path Traversal если `$path` пользовательский |
| `CAgent::AddAgent($string)` | RCE если строка собрана из пользовательского ввода (там eval-подобная семантика) |
| `Loader::includeModule($name)` | Если `$name` управляемый — может загрузить произвольный модуль (LFI-вариант) |
| `CEventLog::Add` | Безопасна, но может содержать sensitive в `DESCRIPTION` |
| `htmlspecialcharsEx` | Делает чуть больше, чем `htmlspecialcharsbx`. Оба ОК для HTML |
| `bitrix_sessid()` | Возвращает токен; используется внутри `check_bitrix_sessid()` |

## Частые ложные срабатывания (проверь до репорта)

| Видишь | Но на самом деле |
|---|---|
| `eval($x)` / `exec($x)` в админ-инструменте, консоли, отладочной панели | назначение модуля; доступ гейтится `IsAdmin()`+`CanDoOperation('edit_php')` или явным токеном/ключом, выданным администратором. Не RCE, если нет обхода проверки |
| `eval()` от значения из БД | настоящий RCE **только** если это значение может записать менее привилегированный пользователь, чем тот, кто вправе исполнять код. Смотри обработчик сохранения: `CanDoOperation('edit_php')`, `GetGroupRight(...,'W')`, `canWrite()` → не находка |
| обфусцированный блок `base64_decode` + `call_user_func` + лицензия | лицензионный загрузчик/телеметрия: не RCE и не Information Disclosure, если нет внешнего ввода и опасного sink |
| `getPublicHashKey()` / короткая метка от лицензии в HTML | публичный ключ лицензии — не секрет, не находка |
| `CURLOPT_SSL_VERIFYPEER => false` к константному адресу вендора | LOW/hardening, не medium-«MITM», если в канале нет секретов |
| `HttpClient::setPrivateIp(false)` | это **запрет** запросов на приватные IP (защита от SSRF), а не ослабление |
| неэкранированный вывод поля, которое сохраняет только администратор (`edit_php`/`W`) | осознанная функциональность (код счётчика, свой HTML), не stored XSS. Прямой `$_REQUEST`/`$_GET` в выводе — по-прежнему XSS |
| `CIBlockElement::SetPropertyValueCode` от анонима | если это публичный счётчик (лайки/просмотры) с серверным учётом — штатно; если иные поля или без учёта — IDOR |
| находка в автономном скрипте восстановления/деплоя без пролога ядра | утилита, выкладываемая администратором на время операции (как штатный `restore.php`): не HIGH, максимум LOW |
| клиент передаёт идентификатор тарифа/варианта расчёта | если сумму считает сервер или провайдер, а клиент лишь выбирает валидный вариант — LOW/MEDIUM, не HIGH |

## Архитектурные ориентиры
- В `lib/` обычно ORM и бизнес-логика — реже entry points
- В `install/components/<vendor>/<component>/` — компоненты Bitrix; `class.php` это часто Controller, `template.php` в `templates/` — frontend
- В `admin/` или `install/admin/` — админ-страницы (нужно проверять `GetGroupRight`)
- В `install/index.php` — инсталлятор; обычно вызывается только при установке, но если доступен извне — может быть проблема
- `updater.php` — выполняется при обновлении; обычно безопасно, но проверь, не содержит ли eval/include с переменной
