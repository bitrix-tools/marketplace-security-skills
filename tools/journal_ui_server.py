#!/usr/bin/env python3
"""Local UI for reviewing Bitrix vulnerability journal findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ALLOWED_DISPOSITIONS = {"open", "false_positive", "accepted_risk"}
DISPOSITION_STATUSES = {"false_positive", "accepted_risk"}
BLOCKING_SEVERITIES = {"high"}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, doc: dict[str, Any]) -> None:
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def normalize_file(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    return re.sub(r"^\./+", "", text)


def vulnerability_fingerprint(vuln: dict[str, Any]) -> str:
    # Severity is deliberately excluded so it matches the updater's fingerprint:
    # a re-triage that changes only the severity stays the same finding.
    parts = [
        normalize_text(vuln.get("type")),
        normalize_file(vuln.get("file")),
        normalize_text(vuln.get("line")),
        normalize_text(vuln.get("description")),
    ]
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:32]


def current_state(journal: dict[str, Any]) -> dict[str, Any]:
    findings = journal.get("findings", [])
    counts = Counter(str(f.get("status")) for f in findings)
    blocking_open = sum(
        1
        for finding in findings
        if finding.get("status") == "open"
        and str(finding.get("severity", "")).lower() in BLOCKING_SEVERITIES
    )
    status = "ready_for_submission"
    if blocking_open:
        status = "blocked"
    elif counts["open"] or counts["false_positive"] or counts["accepted_risk"]:
        status = "needs_review"
    return {
        "status": status,
        "last_run_id": journal.get("current_state", {}).get("last_run_id"),
        "archive_sha256": journal.get("current_state", {}).get("archive_sha256"),
        "open_findings": counts["open"],
        "blocking_findings_open": blocking_open,
        "false_positive_findings": counts["false_positive"],
        "accepted_risk_findings": counts["accepted_risk"],
        "fixed_findings": counts["fixed"],
        "removed_findings": counts["removed"],
        "total_findings": len(findings),
    }


def merge_journal_disposition(
    vuln: dict[str, Any],
    finding: dict[str, Any] | None,
) -> dict[str, Any]:
    """Overlay preserved partner feedback from the cumulative journal for UI display."""
    merged = deepcopy(vuln)
    if not finding:
        return merged

    latest = finding.get("latest_vulnerability")
    if not isinstance(latest, dict):
        return merged

    disposition = latest.get("partner_disposition")
    if isinstance(disposition, dict):
        merged["partner_disposition"] = deepcopy(disposition)
    elif finding.get("status") in DISPOSITION_STATUSES:
        merged["partner_disposition"] = {
            "status": finding["status"],
            "note": "",
            "author": "",
            "updated_at": "",
        }
    return merged


def apply_feedback(
    reviewed_path: Path,
    journal_path: Path,
    updates: list[dict[str, Any]],
) -> dict[str, Any]:
    reviewed = load_json(reviewed_path)
    journal = load_json(journal_path)
    by_fingerprint = {
        vulnerability_fingerprint(vuln): vuln
        for vuln in reviewed.get("data", {}).get("vulnerabilities", [])
    }
    journal_by_fingerprint = {
        str(finding.get("fingerprint")): finding
        for finding in journal.get("findings", [])
    }

    applied = 0
    for update in updates:
        fingerprint = str(update.get("fingerprint", ""))
        status = str(update.get("status", "open"))
        if status not in ALLOWED_DISPOSITIONS:
            raise ValueError(f"Unsupported disposition status: {status}")
        vuln = by_fingerprint.get(fingerprint)
        finding = journal_by_fingerprint.get(fingerprint)
        if not vuln or not finding:
            continue

        note = str(update.get("note", "")).strip()
        author = str(update.get("author", "")).strip()
        disposition = {
            "status": status,
            "note": note,
            "author": author,
            "updated_at": now_iso(),
        }
        if status == "open":
            vuln.pop("partner_disposition", None)
        else:
            vuln["partner_disposition"] = disposition

        finding["status"] = status
        finding["latest_vulnerability"] = vuln
        finding.setdefault("events", []).append(
            {
                "run_id": journal.get("current_state", {}).get("last_run_id"),
                "event": "partner_disposition_updated",
                "at": disposition["updated_at"],
                "status": status,
                "note": note,
                "author": author,
            }
        )
        applied += 1

    reviewed.get("data", {}).setdefault("feedbackSummary", {})["updatedAt"] = now_iso()
    reviewed["data"]["feedbackSummary"]["applied"] = applied
    journal["current_state"] = current_state(journal)
    write_json(reviewed_path, reviewed)
    write_json(journal_path, journal)
    return {
        "applied": applied,
        "updated_at": reviewed["data"]["feedbackSummary"]["updatedAt"],
        "reviewed_path": str(reviewed_path),
        "journal_path": str(journal_path),
        "current_state": journal["current_state"],
    }


HTML = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Journal Review</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0d1117;
      --panel: #151b23;
      --panel-2: #10161d;
      --text: #e6edf3;
      --muted: #8b949e;
      --line: #30363d;
      --line-strong: #3d444d;
      --accent: #2dd4bf;
      --accent-ink: #042f2e;
      --success: #3fb950;
      --danger: #ff7b72;
      --warn: #f2cc60;
      --low: #a5b4fc;
      --shadow: 0 18px 50px rgba(0, 0, 0, .32);
    }
    * { box-sizing: border-box; }
    body { margin: 0; font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }
    header { position: sticky; top: 0; z-index: 10; background: rgba(21, 27, 35, .94); border-bottom: 1px solid var(--line); backdrop-filter: blur(12px); }
    .bar { max-width: 1240px; margin: 0 auto; padding: 14px 20px; display: flex; gap: 16px; align-items: center; justify-content: space-between; }
    h1 { font-size: 18px; margin: 0; font-weight: 650; }
    main { max-width: 1240px; margin: 0 auto; padding: 18px 20px 40px; }
    .metrics { display: grid; grid-template-columns: repeat(5, minmax(120px, 1fr)); gap: 10px; margin-bottom: 16px; }
    .metric, .finding, .trend { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
    .metric { padding: 12px; box-shadow: var(--shadow); }
    .metric b { display: block; font-size: 20px; }
    .metric span, .muted { color: var(--muted); }
    .toolbar { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
    .trend { margin: 0 0 16px; padding: 14px; box-shadow: var(--shadow); }
    .trend-head { display: flex; gap: 12px; align-items: baseline; justify-content: space-between; margin-bottom: 10px; }
    .trend-title { font-weight: 650; font-size: 16px; }
    .trend-caption { color: var(--muted); font-size: 12px; }
    .chart-wrap { height: 260px; min-height: 260px; }
    .chart-empty { display: grid; min-height: 180px; place-items: center; color: var(--muted); border: 1px dashed var(--line-strong); border-radius: 8px; }
    input, select, textarea, button { font: inherit; border: 1px solid var(--line); border-radius: 6px; background: var(--panel-2); color: var(--text); }
    input::placeholder, textarea::placeholder { color: #6e7681; }
    input:focus, select:focus, textarea:focus { outline: 2px solid rgba(45, 212, 191, .28); border-color: var(--accent); }
    input, select { padding: 8px 10px; }
    input[type="search"] { min-width: 280px; }
    button { padding: 8px 12px; cursor: pointer; }
    button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); font-weight: 700; }
    button:disabled { opacity: .55; cursor: not-allowed; }
    .findings { display: grid; gap: 12px; }
    .finding { padding: 14px; box-shadow: var(--shadow); }
    .finding-head { display: grid; grid-template-columns: 1fr auto; gap: 12px; align-items: start; margin-bottom: 10px; }
    .title { font-weight: 650; font-size: 16px; }
    .path { margin-top: 2px; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .chips { display: flex; gap: 6px; flex-wrap: wrap; justify-content: end; }
    .chip { border-radius: 999px; padding: 3px 8px; font-size: 12px; border: 1px solid var(--line-strong); background: #0d1117; }
    .chip.medium { color: var(--warn); border-color: rgba(242, 204, 96, .45); background: rgba(242, 204, 96, .1); }
    .chip.low { color: var(--low); }
    .chip.false_positive { color: #79c0ff; border-color: rgba(121, 192, 255, .45); background: rgba(56, 139, 253, .12); }
    .chip.accepted_risk { color: var(--warn); border-color: rgba(242, 204, 96, .45); background: rgba(242, 204, 96, .1); }
    .grid { display: grid; grid-template-columns: 1.3fr .9fr; gap: 14px; }
    .textblock { white-space: pre-wrap; }
    .evidence { display: grid; gap: 12px; }
    .info-box { border: 1px solid var(--line); border-radius: 8px; background: rgba(13, 17, 23, .42); padding: 10px 12px; }
    .info-box label { color: var(--text); }
    .fix-block { margin: 0; }
    .fix-block summary { cursor: pointer; font-weight: 650; color: var(--accent); }
    .fix-block pre { margin: 10px 0 0; max-height: 280px; overflow: auto; white-space: pre-wrap; border: 1px solid var(--line); border-radius: 6px; background: #0d1117; padding: 10px; color: #d1d9e0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 1.45; }
    label { display: block; font-weight: 600; margin-bottom: 5px; }
    textarea { width: 100%; min-height: 92px; resize: vertical; padding: 9px 10px; }
    .feedback { display: grid; gap: 8px; align-content: start; }
    .status { min-height: 20px; color: var(--muted); }
    .save-state { display: none; margin: 0 0 16px; padding: 12px 14px; border: 1px solid var(--line); border-radius: 8px; background: var(--panel); box-shadow: var(--shadow); }
    .save-state.show { display: block; }
    .save-state.success { border-color: rgba(63, 185, 80, .45); background: rgba(63, 185, 80, .1); }
    .save-state.error { border-color: rgba(255, 123, 114, .55); background: rgba(255, 123, 114, .1); }
    .save-state.pending { border-color: rgba(45, 212, 191, .45); background: rgba(45, 212, 191, .08); }
    .save-state strong { display: block; margin-bottom: 3px; }
    .save-state small { color: var(--muted); }
    @media (max-width: 820px) {
      .metrics, .grid { grid-template-columns: 1fr; }
      .chart-wrap { height: 220px; min-height: 220px; }
      .finding-head { grid-template-columns: 1fr; }
      .chips { justify-content: start; }
      input[type="search"] { min-width: 100%; }
    }
  </style>
</head>
<body>
  <header>
    <div class="bar">
      <h1>Security Journal Review</h1>
      <button class="primary" id="save">Сохранить feedback в JSON</button>
    </div>
  </header>
  <main>
    <section class="metrics" id="metrics"></section>
    <section class="trend" id="trendSection">
      <div class="trend-head">
        <div>
          <div class="trend-title">Динамика проверок</div>
          <div class="trend-caption">X: запуск проверки, Y: количество находок по severity</div>
        </div>
        <span class="trend-caption" id="trendMeta"></span>
      </div>
      <div class="chart-wrap">
        <canvas id="severityTrend"></canvas>
      </div>
    </section>
    <section class="save-state" id="saveState" aria-live="polite"></section>
    <div class="toolbar">
      <input id="query" type="search" placeholder="Файл, тип, описание">
      <select id="statusFilter">
        <option value="">Все статусы</option>
        <option value="open">Open</option>
        <option value="false_positive">False positive</option>
        <option value="accepted_risk">Accepted risk</option>
      </select>
      <select id="severityFilter">
        <option value="">Все severity</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <span class="status" id="status"></span>
    </div>
    <section class="findings" id="findings"></section>
  </main>
  <script src="/vendor/chart.umd.min.js"></script>
  <script>
    let state = { reviewed: null, journal: null, findings: [], feedback: {}, dirty: false };
    let severityChart = null;
    const $ = id => document.getElementById(id);
    const esc = s => String(s ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
    const dispositionOf = vuln => vuln.partner_disposition?.status || 'open';
    const noteOf = vuln => vuln.partner_disposition?.note || '';
    const authorOf = vuln => vuln.partner_disposition?.author || '';

    async function api(path, options) {
      const response = await fetch(path, options);
      if (!response.ok) throw new Error(await response.text());
      return response.json();
    }

    async function load() {
      state = await api('/api/data');
      state.feedback = Object.fromEntries(state.findings.map(item => [
        item.fingerprint,
        {
          status: dispositionOf(item.vulnerability),
          author: authorOf(item.vulnerability),
          note: noteOf(item.vulnerability),
        }
      ]));
      state.dirty = false;
      render();
    }

    function renderMetrics() {
      const counts = state.journal.current_state || {};
      const metrics = [
        ['Open', counts.open_findings ?? 0],
        ['False positive', counts.false_positive_findings ?? 0],
        ['Accepted risk', counts.accepted_risk_findings ?? 0],
        ['Blocking', counts.blocking_findings_open ?? 0],
        ['Total', counts.total_findings ?? state.findings.length],
      ];
      $('metrics').innerHTML = metrics.map(([label, value]) => `<div class="metric"><b>${value}</b><span>${label}</span></div>`).join('');
    }

    function inferSeverityCounts(runId) {
      const counts = {};
      for (const item of state.findings) {
        const finding = item.journal || {};
        const seenInRun = finding.last_seen_run_id === runId ||
          (finding.events || []).some(event => event.run_id === runId && ['detected', 'detected_again', 'reopened'].includes(event.event));
        if (!seenInRun) continue;
        const severity = String((finding.latest_vulnerability || item.vulnerability || {}).severity || finding.severity || '').toLowerCase();
        if (severity) counts[severity] = (counts[severity] || 0) + 1;
      }
      return counts;
    }

    function runTrendRows() {
      return (state.journal.runs || []).map((run, index) => {
        const counts = run.summary?.severity_counts || inferSeverityCounts(run.run_id);
        return {
          label: `${index + 1}`,
          runId: run.run_id,
          counts,
        };
      });
    }

    function renderTrend() {
      const rows = runTrendRows();
      const section = $('trendSection');
      if (rows.length <= 1) {
        section.style.display = 'none';
        if (severityChart) {
          severityChart.destroy();
          severityChart = null;
        }
        return;
      }
      section.style.display = '';
      $('trendMeta').textContent = rows.length ? `${rows.length} запуск(ов)` : 'Истории пока нет';
      const wrap = document.querySelector('.chart-wrap');
      if (!rows.length) {
        wrap.innerHTML = '<div class="chart-empty">История появится после первого запуска проверки.</div>';
        return;
      }
      if (!window.Chart) {
        wrap.innerHTML = '<div class="chart-empty">Chart.js не загрузился, график недоступен.</div>';
        return;
      }
      if (!document.getElementById('severityTrend')) {
        wrap.innerHTML = '<canvas id="severityTrend"></canvas>';
      }
      const labels = rows.map(row => row.label);
      const colors = {
        high: '#ff7b72',
        medium: '#f2cc60',
        low: '#a5b4fc',
      };
      const datasets = ['high', 'medium', 'low']
        .filter(severity => rows.some(row => Number(row.counts[severity] || 0) > 0))
        .map(severity => ({
          label: severity,
          data: rows.map(row => Number(row.counts[severity] || 0)),
          borderColor: colors[severity],
          backgroundColor: colors[severity],
          tension: .28,
          pointRadius: 4,
          pointHoverRadius: 6,
        }));
      if (severityChart) severityChart.destroy();
      severityChart = new Chart(document.getElementById('severityTrend'), {
        type: 'line',
        data: { labels, datasets },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: 'index', intersect: false },
          plugins: {
            legend: { labels: { color: '#e6edf3', boxWidth: 10, usePointStyle: true } },
            tooltip: {
              callbacks: {
                title: items => {
                  const row = rows[items[0].dataIndex];
                  return `Запуск ${row.label}: ${row.runId}`;
                }
              }
            }
          },
          scales: {
            x: {
              title: { display: true, text: 'Запуск проверки', color: '#8b949e' },
              ticks: { color: '#8b949e' },
              grid: { color: 'rgba(48, 54, 61, .7)' },
            },
            y: {
              beginAtZero: true,
              ticks: { color: '#8b949e', precision: 0 },
              title: { display: true, text: 'Количество уязвимостей', color: '#8b949e' },
              grid: { color: 'rgba(48, 54, 61, .7)' },
            },
          },
        },
      });
    }

    function renderFindings() {
      const q = $('query').value.trim().toLowerCase();
      const status = $('statusFilter').value;
      const severity = $('severityFilter').value;
      const rows = state.findings.filter(item => {
        const vuln = item.vulnerability;
        const draft = state.feedback[item.fingerprint] || {};
        const haystack = `${vuln.file} ${vuln.type} ${vuln.description}`.toLowerCase();
        return (!q || haystack.includes(q)) &&
          (!status || (draft.status || dispositionOf(vuln)) === status) &&
          (!severity || vuln.severity === severity);
      });
      $('findings').innerHTML = rows.map(item => {
        const vuln = item.vulnerability;
        const draft = state.feedback[item.fingerprint] || {};
        const disp = draft.status || dispositionOf(vuln);
        return `<article class="finding" data-fingerprint="${esc(item.fingerprint)}">
          <div class="finding-head">
            <div>
              <div class="title">${esc(vuln.type)}</div>
              <div class="path">${esc(vuln.file)}:${esc(vuln.line)}</div>
            </div>
            <div class="chips">
              <span class="chip ${esc(vuln.severity)}">${esc(vuln.severity)}</span>
              <span class="chip ${esc(disp)}">${esc(disp)}</span>
            </div>
          </div>
          <div class="grid">
            <div class="evidence">
              <div class="info-box">
                <label>Описание</label>
                <div class="textblock">${esc(vuln.description)}</div>
              </div>
              <div class="info-box">
                <label>Рекомендация</label>
                <div class="textblock">${esc(vuln.recommendation || 'Рекомендация не указана.')}</div>
              </div>
              ${vuln.fix ? `<details class="info-box fix-block"><summary>Вариант исправления</summary><pre>${esc(vuln.fix)}</pre></details>` : ''}
              <p class="muted">${esc(vuln.reviewed?.rationale || '')}</p>
            </div>
            <div class="feedback">
              <label>Мнение разработчика</label>
              <select data-field="status">
                <option value="open" ${disp === 'open' ? 'selected' : ''}>Open</option>
                <option value="false_positive" ${disp === 'false_positive' ? 'selected' : ''}>False positive</option>
                <option value="accepted_risk" ${disp === 'accepted_risk' ? 'selected' : ''}>Accepted risk</option>
              </select>
              <input data-field="author" placeholder="Автор" value="${esc(draft.author ?? authorOf(vuln))}">
              <textarea data-field="note" placeholder="Почему это не уязвимость или почему риск принят">${esc(draft.note ?? noteOf(vuln))}</textarea>
            </div>
          </div>
        </article>`;
      }).join('') || '<p class="muted">Ничего не найдено.</p>';
    }

    function render() {
      renderMetrics();
      renderTrend();
      renderFindings();
      $('status').textContent = state.dirty ? 'Есть несохраненные изменения' : '';
    }

    function showSaveState(kind, title, details = '') {
      const node = $('saveState');
      node.className = `save-state show ${kind}`;
      node.innerHTML = `<strong>${esc(title)}</strong>${details ? `<small>${esc(details)}</small>` : ''}`;
    }

    function collectUpdates() {
      return Object.entries(state.feedback).map(([fingerprint, draft]) => ({
        fingerprint,
        status: draft.status || 'open',
        author: draft.author || '',
        note: draft.note || '',
      }));
    }

    function updateDraft(target) {
      const card = target.closest('.finding');
      if (!card) return;
      state.feedback[card.dataset.fingerprint] ||= {};
      state.feedback[card.dataset.fingerprint][target.dataset.field] = target.value;
      state.dirty = true;
      $('status').textContent = 'Есть несохраненные изменения';
    }

    document.addEventListener('change', event => {
      if (event.target.matches('[data-field]')) {
        updateDraft(event.target);
        if (event.target.dataset.field === 'status') render();
      } else if (event.target.matches('#statusFilter, #severityFilter')) {
        renderFindings();
      }
    });
    document.addEventListener('input', event => {
      if (event.target.matches('[data-field]')) updateDraft(event.target);
      if (event.target.matches('#query')) renderFindings();
    });
    $('save').addEventListener('click', async () => {
      const previousLabel = $('save').textContent;
      $('save').disabled = true;
      $('save').textContent = 'Сохраняю...';
      $('status').textContent = 'Сохраняю...';
      showSaveState('pending', 'Сохраняю feedback в JSON', 'Обновляю reviewed scan и cumulative security journal.');
      try {
        const result = await api('/api/feedback', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({updates: collectUpdates()}),
        });
        await load();
        const counts = result.current_state || {};
        $('status').textContent = 'Журнал сохранен';
        showSaveState(
          'success',
          `Журнал сохранен: применено ${result.applied} изменений`,
          `Open: ${counts.open_findings ?? 0}, false positive: ${counts.false_positive_findings ?? 0}, accepted risk: ${counts.accepted_risk_findings ?? 0}. Дальше можно продолжить разметку или отправить security-journal.json.`
        );
      } catch (error) {
        $('status').textContent = error.message;
        showSaveState('error', 'Не удалось сохранить журнал', error.message);
      } finally {
        $('save').disabled = false;
        $('save').textContent = previousLabel;
      }
    });
    load().catch(error => $('status').textContent = error.message);
  </script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    reviewed_path: Path
    journal_path: Path
    vendor_dir: Path

    def send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html"}:
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if self.path == "/vendor/chart.umd.min.js":
            chart_path = self.vendor_dir / "chart.umd.min.js"
            if not chart_path.is_file():
                self.send_error(404)
                return
            body = chart_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/data":
            reviewed = load_json(self.reviewed_path)
            journal = load_json(self.journal_path)
            journal_by_fp = {str(f.get("fingerprint")): f for f in journal.get("findings", [])}
            findings = []
            for vuln in reviewed.get("data", {}).get("vulnerabilities", []):
                fingerprint = vulnerability_fingerprint(vuln)
                finding = journal_by_fp.get(fingerprint)
                findings.append(
                    {
                        "fingerprint": fingerprint,
                        "vulnerability": merge_journal_disposition(vuln, finding),
                        "journal": finding,
                    }
                )
            self.send_json({"reviewed": reviewed, "journal": journal, "findings": findings})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if self.path != "/api/feedback":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        try:
            result = apply_feedback(
                self.reviewed_path,
                self.journal_path,
                payload.get("updates", []),
            )
        except Exception as exc:
            self.send_json({"error": str(exc)}, 400)
            return
        self.send_json(result)


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve local vulnerability review UI")
    parser.add_argument("--reviewed", type=Path, default=Path(".reports/lib.reviewed.json"))
    parser.add_argument("--journal", type=Path, default=Path(".reports/security-journal.json"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    Handler.reviewed_path = args.reviewed
    Handler.journal_path = args.journal
    Handler.vendor_dir = Path(__file__).resolve().parent / "vendor"
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"http://{args.host}:{args.port}/")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
