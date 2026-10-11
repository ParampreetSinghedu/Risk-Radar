/* Risk Radar Stage 13 dashboard.
 * Talks only to the real FastAPI backend. Never fabricates data: every panel
 * shows an explicit loading, empty, or error state when results are absent. */
"use strict";

const API = "/api/v1";
const store = { lastInvestigation: null, snapshots: [] };

/* ---------- tiny helpers ---------- */
const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function flash(msg, ok = true) {
  const el = $("#flash");
  el.className = "flash " + (ok ? "ok" : "err");
  el.textContent = msg;
  setTimeout(() => { el.className = "flash"; }, 4200);
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.status === 204 ? null : res.json();
}

function badge(text, cls) { return `<span class="badge ${cls}">${esc(text)}</span>`; }

function gateBadge(outcome) {
  if (outcome === "verified_official") return badge("verified official", "b-ok");
  if (outcome === "unverified") return badge("unverified", "b-warn");
  if (outcome === "not_matched") return badge("not matched", "b-bad");
  return badge(outcome || "unknown", "b-muted");
}
function statusBadge(s) {
  if (s === "open") return badge("open", "b-info");
  if (s === "in_review") return badge("in review", "b-warn");
  if (s === "closed") return badge("closed", "b-muted");
  return badge(s, "b-muted");
}
function stageBadge(s) {
  if (s === "completed" || s === "scored" || s === "evaluated") return badge(s, "b-ok");
  if (s === "partial") return badge(s, "b-warn");
  if (s === "failed" || s === "failed_closed") return badge(s, "b-bad");
  if (s === "unavailable" || s === "no_model" || s === "no_evidence" || s === "provider_unavailable")
    return badge(s, "b-muted");
  return badge(s || "n/a", "b-muted");
}
function fmtDate(s) { return s ? new Date(s).toLocaleString() : "—"; }

/* ---------- navigation ---------- */
document.querySelectorAll("#nav button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#nav button").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    btn.classList.add("active");
    $("#view-" + btn.dataset.view).classList.add("active");
    if (btn.dataset.view === "dashboard") loadDashboard();
    if (btn.dataset.view === "cases") loadCases();
    if (btn.dataset.view === "alerts") loadAlerts();
  });
});

/* ---------- dashboard ---------- */
async function loadDashboard() {
  const cards = $("#dash-cards"), recent = $("#dash-recent");
  cards.innerHTML = ""; recent.innerHTML = "<div class='state'>Loading…</div>";
  try {
    const d = await api("/dashboard");
    const defs = [
      ["Total cases", d.total_cases, ""],
      ["Open", d.open_cases, ""],
      ["In review", d.in_review_cases, ""],
      ["Closed", d.closed_cases, ""],
      ["Alert-eligible", d.alert_eligible_cases, ""],
      ["Verified official", d.verified_official_cases, ""],
    ];
    cards.innerHTML = defs.map(([lbl, num]) =>
      `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="num">${num}</div></div>`).join("");
    if (!d.recent_cases.length) {
      recent.innerHTML = "<div class='state'>No cases yet. Open one from the Cases tab.</div>";
    } else {
      recent.innerHTML = caseTable(d.recent_cases, false);
      bindRowClicks(recent);
    }
  } catch (e) {
    cards.innerHTML = "";
    recent.innerHTML = `<div class='state error'>Could not load dashboard: ${esc(e.message)}</div>`;
  }
}

/* ---------- submit ---------- */
$("#sub-btn").addEventListener("click", async () => {
  const out = $("#sub-result");
  out.innerHTML = "<div class='state'>Storing…</div>";
  try {
    const body = {
      submission_type: $("#sub-type").value,
      content: $("#sub-content").value.trim(),
      source: $("#sub-source").value.trim() || "user",
    };
    const r = await api("/submissions", { method: "POST", body: JSON.stringify(body) });
    out.innerHTML = `<div class="panel" style="margin-top:14px">
      <h3>Stored submission</h3>
      <div class="kv">
        <div class="k">Submission id</div><div class="mono">#${r.id}</div>
        <div class="k">Type</div><div>${esc(r.submission_type)}</div>
        <div class="k">Content hash</div><div class="mono">${esc(r.content_hash.slice(0, 24))}…</div>
        <div class="k">Stored at</div><div>${fmtDate(r.created_at)}</div>
      </div></div>`;
    flash(`Submission #${r.id} stored`);
  } catch (e) {
    out.innerHTML = `<div class='state error'>${esc(e.message)}</div>`;
  }
});

/* ---------- investigate ---------- */
$("#inv-btn").addEventListener("click", runPipeline);
async function runPipeline() {
  const target = $("#inv-target").value.trim();
  const out = $("#inv-result");
  if (!target) { flash("Enter a target first", false); return; }
  out.innerHTML = "<div class='state'>Running pipeline…</div>";
  const stage = {};
  const render = () => { out.innerHTML = renderInvestigation(target, stage); };

  // Run each stage independently; capture results or errors per stage.
  const jobs = [
    ["gate", () => api("/gate/evaluate", { method: "POST", body: JSON.stringify({ target }) })],
    ["evidence", () => api("/evidence/analyze", { method: "POST", body: JSON.stringify({ target }) })],
    ["rules", () => api("/rules/evaluate", { method: "POST", body: JSON.stringify({ target }) })],
    ["risk", () => api("/risk/score", { method: "POST", body: JSON.stringify({ target }) })],
    ["rag", () => api("/rag/analyze", { method: "POST", body: JSON.stringify({ target }) })],
    ["investigate", () => api("/investigate", { method: "POST", body: JSON.stringify({ target }) })],
  ];
  await Promise.all(jobs.map(async ([key, fn]) => {
    try { stage[key] = { ok: true, data: await fn() }; }
    catch (e) { stage[key] = { ok: false, error: e.message }; }
    render();
  }));
  // Keep the last investigation so it can be attached to a case.
  store.lastInvestigation = { target, stage };
  store.snapshots.push({ label: `${target} — ${new Date().toLocaleTimeString()}`, snapshot: buildSnapshot(stage) });
  refreshSnapshotOptions();
  flash("Pipeline complete");
}

function buildSnapshot(stage) {
  const snap = {};
  for (const [k, v] of Object.entries(stage)) if (v.ok) snap[k] = v.data;
  return snap;
}

function renderInvestigation(target, stage) {
  const gate = stage.gate;
  let gateLine = "<div class='state'>Loading…</div>";
  if (gate) {
    if (!gate.ok) gateLine = `<div class='state error'>Gate failed: ${esc(gate.error)}</div>`;
    else gateLine = `<div class="kv">
        <div class="k">Outcome</div><div>${gateBadge(gate.data.outcome)}</div>
        <div class="k">Alert eligible</div><div>${gate.data.alert_eligible ? badge("yes", "b-bad") : badge("no", "b-ok")}</div>
        <div class="k">Reason</div><div>${esc(gate.data.reason)}</div>
        <div class="k">Audit id</div><div class="mono">${gate.data.audit_id ?? "—"}</div>
      </div>`;
  }
  return `
  <div class="panel" style="margin-top:16px">
    <h2>Stage 6 — Exclusion gate</h2>${gateLine}
  </div>
  ${stagePanel("Stage 5 — Multimodal evidence", stage.evidence, renderEvidence)}
  ${stagePanel("Stage 7 — Rule findings", stage.rules, renderRules)}
  ${stagePanel("Stage 11 — Risk × Impact", stage.risk, renderRisk)}
  ${stagePanel("Stage 12 — Grounded analysis", stage.rag, renderRag)}
  ${stagePanel("Stage 9 — Investigation findings", stage.investigate, renderInvestigate)}`;
}

function stagePanel(title, res, renderer) {
  let body;
  if (!res) body = "<div class='state'>Pending…</div>";
  else if (!res.ok) body = `<div class='state error'>${esc(res.error)}</div>`;
  else body = renderer(res.data);
  return `<div class="panel"><h2>${esc(title)}</h2>${body}</div>`;
}

function renderEvidence(data) {
  const rows = (data.summaries || []).map((s) =>
    `<tr><td>${esc(s.analyzer)}</td><td>${stageBadge(s.status)}</td>
     <td>${s.observation_count} obs / ${s.indicator_count} ind</td>
     <td>${s.limitation_count} lim / ${s.error_count} err</td></tr>`).join("");
  const detail = (data.results || []).map((r) => {
    const obs = (r.observations || []).map((o) =>
      `<li><span class="tag">${esc(o.kind)}</span> <span class="mono">${esc(JSON.stringify(o.value).slice(0, 90))}</span></li>`).join("");
    const lim = (r.limitations || []).map((l) => `<li>${esc(l)}</li>`).join("");
    return `<div class="section-block"><h3>${esc(r.analyzer_type)} — ${esc(r.status)}</h3>
      ${obs ? `<ul class="list">${obs}</ul>` : "<div class='muted' style='font-size:12.5px'>No observations.</div>"}
      ${lim ? `<h3>Limitations</h3><ul class="list">${lim}</ul>` : ""}</div>`;
  }).join("");
  return `${rows ? `<table><tr><th>Analyzer</th><th>Status</th><th>Signals</th><th>Notes</th></tr>${rows}</table>` : "<div class='state'>No analyzer results.</div>"}${detail}`;
}

function renderRules(data) {
  const findings = (data.findings || []).map((f) =>
    `<tr><td>${esc(f.rule_id)}</td><td>${badge(f.severity, sevClass(f.severity))}</td>
     <td>${esc(f.reason)}</td><td class="mono">${esc((f.evidence_refs || []).join(", "))}</td></tr>`).join("");
  const skipped = (data.skipped || []).map((s) => `<li><b>${esc(s.rule_id)}</b>: ${esc(s.reason)}</li>`).join("");
  return `<div style="margin-bottom:8px">Status: ${stageBadge(data.status)}</div>
    ${findings ? `<table><tr><th>Rule</th><th>Severity</th><th>Reason</th><th>Evidence</th></tr>${findings}</table>`
      : "<div class='state'>No rules matched.</div>"}
    ${skipped ? `<h3>Skipped rules</h3><ul class="list">${skipped}</ul>` : ""}`;
}

function sevClass(s) {
  return { critical: "b-bad", high: "b-bad", medium: "b-warn", low: "b-info", informational: "b-muted" }[s] || "b-muted";
}

function renderRisk(data) {
  if (data.status !== "scored") {
    return `<div class="kv"><div class="k">Status</div><div>${stageBadge(data.status)}</div>
      <div class="k">Limitations</div><ul class="list">${(data.limitations || []).map((l) => `<li>${esc(l)}</li>`).join("")}</ul></div>`;
  }
  const d = data.detection_risk || {}, imp = data.business_impact || {};
  const sigs = (d.signals || []).map((s) =>
    `<li>${esc(s.name)} → <span class="mono">${s.contribution}</span>: ${esc(s.reason)}</li>`).join("");
  return `<div class="kv">
      <div class="k">Overall score</div><div><b>${data.overall_score}</b> <span class="tag">ranking, not a probability</span></div>
      <div class="k">Detection risk</div><div>${d.score ?? "—"} (rule ${d.rule_risk ?? "—"} / ml ${d.ml_risk ?? "n/a"})</div>
      <div class="k">Business impact</div><div>${imp.status === "available" ? imp.score : badge("unavailable", "b-muted")}</div>
      <div class="k">Formula</div><div class="mono" style="font-size:11.5px">${esc(data.overall_formula || "")}</div>
    </div>
    ${sigs ? `<h3>Contributing signals</h3><ul class="list">${sigs}</ul>` : ""}
    ${(imp.missing_data || []).length ? `<h3>Missing impact data</h3><ul class="list">${imp.missing_data.map((m) => `<li class="muted">${esc(m)}</li>`).join("")}</ul>` : ""}`;
}

function renderRag(data) {
  if (["provider_unavailable", "no_evidence"].includes(data.status)) {
    return `<div class="kv"><div class="k">Status</div><div>${stageBadge(data.status)}</div></div>
      <ul class="list">${(data.limitations || []).map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`;
  }
  const docs = (data.retrieved_documents || []).map((d) =>
    `<li><span class="mono">${esc(d.doc_id)}</span> <span class="tag">${esc(d.source_type)}</span> rel ${d.relevance}</li>`).join("");
  const claims = (data.claims || []).map((c) => {
    const cites = (c.citations || []).map((x) => `<code>${esc(x.doc_id)}</code>`).join(" ");
    return `<li><span class="tag">${esc(c.kind)}</span> ${esc(c.text)} ${cites}</li>`;
  }).join("");
  const rej = (data.rejected_claims || []).length;
  return `<div style="margin-bottom:8px">Status: ${stageBadge(data.status)}</div>
    ${docs ? `<h3>Retrieved documents</h3><ul class="list">${docs}</ul>` : "<div class='muted' style='font-size:12.5px'>No documents retrieved.</div>"}
    ${claims ? `<h3>Claims (citation-validated)</h3><ul class="list">${claims}</ul>` : "<div class='state'>No claims generated.</div>"}
    ${rej ? `<div class="muted" style="font-size:12.5px">${rej} claim(s) rejected (unsupported/uncited).</div>` : ""}`;
}

function renderInvestigate(data) {
  const findings = (data.findings || []).map((f) => {
    const cites = (f.citations || []).map((c) => `<code>${esc(c.reference)}</code>`).join(" ");
    return `<li>${esc(f.finding)} ${cites}</li>`;
  }).join("");
  if (!findings) {
    return `<div class="kv"><div class="k">Status</div><div>${stageBadge(data.status)}</div></div>
      <ul class="list">${(data.limitations || []).map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`;
  }
  return `<div style="margin-bottom:8px">Status: ${stageBadge(data.status)}</div><ul class="list">${findings}</ul>`;
}

/* ---------- cases ---------- */
function caseTable(cases, clickable = true) {
  const rows = cases.map((c) =>
    `<tr class="${clickable ? "row" : ""}" data-id="${c.id}">
      <td class="mono">#${c.id}</td><td>${esc(c.title)}</td>
      <td class="mono" style="max-width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(c.target)}</td>
      <td>${statusBadge(c.status)}</td><td>${gateBadge(c.gate_outcome)}</td>
      <td>${c.alert_eligible ? badge("eligible", "b-bad") : badge("no", "b-ok")}</td>
      <td class="muted">${fmtDate(c.created_at)}</td></tr>`).join("");
  return `<table><tr><th>Id</th><th>Title</th><th>Target</th><th>Status</th><th>Gate</th><th>Alert</th><th>Created</th></tr>${rows}</table>`;
}

function bindRowClicks(container) {
  container.querySelectorAll("tr.row").forEach((tr) =>
    tr.addEventListener("click", () => showCaseDetail(tr.dataset.id)));
}

async function loadCases() {
  const list = $("#cases-list");
  list.innerHTML = "<div class='state'>Loading…</div>";
  try {
    const filter = $("#case-filter").value;
    const q = filter ? `?case_status=${filter}` : "";
    const cases = await api("/cases" + q);
    if (!cases.length) { list.innerHTML = "<div class='state'>No cases match. Open one from the panel above.</div>"; }
    else { list.innerHTML = caseTable(cases); bindRowClicks(list); }
  } catch (e) {
    list.innerHTML = `<div class='state error'>${esc(e.message)}</div>`;
  }
}
$("#case-refresh").addEventListener("click", loadCases);
$("#case-filter").addEventListener("change", loadCases);

$("#case-btn").addEventListener("click", async () => {
  try {
    const body = {
      title: $("#case-title").value.trim(),
      target: $("#case-target").value.trim(),
    };
    if (!body.title || !body.target) { flash("Title and target are required", false); return; }
    const snapSel = $("#case-snapshot").value;
    if (snapSel !== "") body.snapshot = store.snapshots[+snapSel].snapshot;
    const note = $("#case-note").value.trim();
    if (note) body.note = note;
    const c = await api("/cases", { method: "POST", body: JSON.stringify(body) });
    flash(`Case #${c.id} opened (${c.gate_outcome})`);
    loadCases(); loadDashboard();
  } catch (e) { flash(e.message, false); }
});

function refreshSnapshotOptions() {
  const sel = $("#case-snapshot");
  sel.innerHTML = "<option value=''>No snapshot</option>" +
    store.snapshots.map((s, i) => `<option value="${i}">${esc(s.label)}</option>`).join("");
}

async function showCaseDetail(id) {
  const el = $("#case-detail");
  el.style.display = "block";
  el.innerHTML = "<div class='state'>Loading…</div>";
  try {
    const c = await api(`/cases/${id}`);
    const events = (c.events || []).map((e) =>
      `<li><span class="tag">${esc(e.event_type)}</span> <b>${esc(e.actor)}</b> · ${fmtDate(e.created_at)}<br>${esc(e.note)}</li>`).join("");
    el.innerHTML = `<h2>Case #${c.id} — ${esc(c.title)}</h2>
      <div class="kv">
        <div class="k">Target</div><div class="mono">${esc(c.target)}</div>
        <div class="k">Status</div><div>${statusBadge(c.status)}</div>
        <div class="k">Gate outcome</div><div>${gateBadge(c.gate_outcome)}</div>
        <div class="k">Alert eligible</div><div>${c.alert_eligible ? badge("yes", "b-bad") : badge("no", "b-ok")}</div>
        <div class="k">Created</div><div>${fmtDate(c.created_at)}</div>
        <div class="k">Updated</div><div>${fmtDate(c.updated_at)}</div>
      </div>
      <h3>Move workflow</h3>
      <button class="btn sm secondary" data-act="open">Open</button>
      <button class="btn sm secondary" data-act="in_review">In review</button>
      <button class="btn sm secondary" data-act="closed">Close</button>
      <h3>Record analyst decision / note</h3>
      <textarea id="ev-note" placeholder="Analyst decision or note"></textarea>
      <button class="btn sm" id="ev-btn">Add note</button>
      <h3>Timeline</h3>
      ${events ? `<ul class="list">${events}</ul>` : "<div class='muted' style='font-size:12.5px'>No events yet.</div>"}
      <h3>Report</h3>
      <button class="btn sm secondary" id="rep-btn">Generate report</button>`;
    el.querySelectorAll("button[data-act]").forEach((b) =>
      b.addEventListener("click", async () => {
        await api(`/cases/${id}/status`, { method: "PATCH", body: JSON.stringify({ status: b.dataset.act }) });
        flash(`Case #${id} → ${b.dataset.act}`);
        showCaseDetail(id); loadCases();
      }));
    $("#ev-btn").addEventListener("click", async () => {
      const note = $("#ev-note").value.trim();
      if (!note) { flash("Enter a note", false); return; }
      await api(`/cases/${id}/events`, { method: "POST", body: JSON.stringify({ event_type: "decision", note }) });
      flash("Decision recorded"); showCaseDetail(id);
    });
    $("#rep-btn").addEventListener("click", () => { showReport(id); switchView("alerts"); });
  } catch (e) { el.innerHTML = `<div class='state error'>${esc(e.message)}</div>`; }
}

/* ---------- alerts / reports ---------- */
async function loadAlerts() {
  const list = $("#alerts-list");
  list.innerHTML = "<div class='state'>Loading…</div>";
  try {
    const cases = await api("/cases");
    const eligible = cases.filter((c) => c.alert_eligible);
    if (!eligible.length) {
      list.innerHTML = "<div class='state'>No alert-eligible cases. Verified official assets are excluded by the gate.</div>";
    } else {
      list.innerHTML = caseTable(eligible);
      list.querySelectorAll("tr.row").forEach((tr) =>
        tr.addEventListener("click", () => { showReport(tr.dataset.id); }));
    }
  } catch (e) { list.innerHTML = `<div class='state error'>${esc(e.message)}</div>`; }
}

async function showReport(id) {
  const el = $("#report-panel");
  el.style.display = "block";
  el.innerHTML = "<div class='state'>Generating report…</div>";
  try {
    const r = await api(`/cases/${id}/report`);
    const sections = r.report_sections.map((s) => `<li>${esc(s)}</li>`).join("");
    const events = r.analyst_events.map((e) =>
      `<li><span class="tag">${esc(e.event_type)}</span> <b>${esc(e.actor)}</b> · ${fmtDate(e.created_at)}<br>${esc(e.note)}</li>`).join("");
    const lims = r.limitations.map((l) => `<li class="muted">${esc(l)}</li>`).join("");
    el.innerHTML = `<h2>Case report — #${r.case_id} ${esc(r.title)}</h2>
      <ul class="list">${sections}</ul>
      ${events ? `<h3>Analyst decisions</h3><ul class="list">${events}</ul>` : ""}
      ${lims ? `<h3>Report limitations</h3><ul class="list">${lims}</ul>` : ""}
      ${r.snapshot ? `<h3>Attached stage snapshot</h3><div class="mono" style="font-size:12px;white-space:pre-wrap;max-height:260px;overflow:auto">${esc(JSON.stringify(r.snapshot, null, 2))}</div>` : ""}
      <button class="btn sm secondary" onclick="document.getElementById('report-panel').style.display='none'">Hide report</button>`;
  } catch (e) { el.innerHTML = `<div class='state error'>${esc(e.message)}</div>`; }
}

function switchView(name) {
  document.querySelectorAll("#nav button").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  $("#view-" + name).classList.add("active");
}

/* ---------- init ---------- */
loadDashboard();
