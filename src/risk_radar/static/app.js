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
function verdictBadge(v) {
  if (v === "malicious") return badge("malicious", "b-bad");
  if (v === "benign") return badge("benign", "b-ok");
  if (v === "suspicious") return badge("suspicious", "b-warn");
  return badge(v || "unknown", "b-muted");
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

/* ---------- persisted monitoring ---------- */
async function loadMonitoring() {
  const targetsEl = $("#mon-targets"), alertsEl = $("#mon-alerts");
  targetsEl.innerHTML = alertsEl.innerHTML = "<div class='state'>Loading…</div>";
  const results = await Promise.allSettled([
    api("/monitoring/targets"), api("/monitoring/alerts"), api("/monitoring/status"),
  ]);
  const [targetsResult, alertsResult, runtimeResult] = results;
  if (runtimeResult.status === "fulfilled") {
    const runtime = runtimeResult.value;
    $("#mon-status").innerHTML = `<b>Scheduler:</b> ${runtime.scheduler_enabled ? "enabled" : "disabled; checks can be run manually"}<br><b>Targets:</b> ${targetsResult.status === "fulfilled" ? `${targetsResult.value.length}; ${targetsResult.value.filter((target) => target.active_monitoring).length} with a successful check.` : "unavailable"}<br><b>Providers:</b><ul class="list">${Object.entries(runtime.providers).map(([name, status]) => `<li>${esc(name)}: ${esc(status)}</li>`).join("")}</ul>`;
  } else {
    $("#mon-status").innerHTML = `<div class='state error'>Monitoring status unavailable: ${esc(runtimeResult.reason.message)}</div>`;
  }
  if (targetsResult.status === "fulfilled") {
    const targets = targetsResult.value;
    if (!targets.length) {
      targetsEl.innerHTML = "<div class='state'>Create a target to begin recording checks.</div>";
    } else {
      targetsEl.innerHTML = `<table><thead><tr><th>Target</th><th>Status</th><th>Interval</th><th>Last check</th><th>Next check</th><th>Provider status</th><th>Actions</th></tr></thead><tbody>${targets.map((target) => {
        const label = target.removed ? "removed" : !target.enabled ? "paused" : target.active_monitoring ? "active" : target.last_status === "never_checked" ? "waiting for first successful check" : `not active — ${target.last_status}`;
        return `<tr><td><b>${esc(target.target_type)}</b><br><span class="mono">${esc(target.target)}</span></td><td>${esc(label)}</td><td>${target.interval_seconds}s</td><td>${fmtDate(target.last_check_at)}${target.last_success_at ? `<br><span class="muted">successful ${fmtDate(target.last_success_at)}</span>` : ""}</td><td>${fmtDate(target.next_check_at)}</td><td>${target.last_error ? `<span class="muted">${esc(target.last_error)}</span>` : esc(target.last_status)}</td><td>${target.enabled ? `<button class="btn sm secondary" data-mon-action="pause" data-id="${target.id}">Pause</button>` : `<button class="btn sm secondary" data-mon-action="resume" data-id="${target.id}">Resume</button>`}<button class="btn sm secondary" data-mon-action="check" data-id="${target.id}">Check now</button><button class="btn sm secondary" data-mon-action="history" data-id="${target.id}">History</button><button class="btn sm secondary" data-mon-action="remove" data-id="${target.id}">Remove</button></td></tr>`;
      }).join("")}</tbody></table>`;
      targetsEl.querySelectorAll("button[data-mon-action]").forEach((button) => button.addEventListener("click", () => handleMonitoringAction(button)));
    }
  } else {
    targetsEl.innerHTML = `<div class='state error'>Targets unavailable: ${esc(targetsResult.reason.message)}</div>`;
  }
  if (alertsResult.status === "fulfilled") renderMonitoringAlerts(alertsResult.value);
  else alertsEl.innerHTML = `<div class='state error'>Alerts unavailable: ${esc(alertsResult.reason.message)}</div>`;
}

function renderMonitoringAlerts(alerts) {
  const el = $("#mon-alerts");
  if (!alerts.length) { el.innerHTML = "<div class='state'>No monitoring changes recorded.</div>"; return; }
  el.innerHTML = `<table><thead><tr><th>Created</th><th>Target</th><th>Change</th><th>Evidence</th><th>Review</th><th>Case</th></tr></thead><tbody>${alerts.map((alert) => `<tr><td>${fmtDate(alert.created_at)}</td><td><span class="mono">${esc(alert.target)}</span></td><td>${esc(alert.change_type)}<br>${esc(alert.summary)}</td><td><details><summary>Check #${alert.check_id}</summary><pre class="mono">${esc(JSON.stringify(alert.evidence, null, 2))}</pre></details></td><td>${alert.acknowledged_at ? `Acknowledged by ${esc(alert.acknowledged_by)}<br>${fmtDate(alert.acknowledged_at)}` : `<button class="btn sm secondary" data-alert-ack="${alert.id}">Acknowledge</button>`}</td><td><button class="btn sm secondary" data-alert-case="${alert.id}">Create case</button></td></tr>`).join("")}</tbody></table>`;
  const byId = new Map(alerts.map((alert) => [String(alert.id), alert]));
  el.querySelectorAll("button[data-alert-ack]").forEach((button) => button.addEventListener("click", async () => {
    try {
      await api(`/monitoring/alerts/${button.dataset.alertAck}/acknowledge`, { method: "POST", body: JSON.stringify({ acknowledged_by: "analyst" }) });
      flash("Monitoring alert acknowledged");
      loadMonitoring();
    } catch (e) { flash(e.message, false); }
  }));
  el.querySelectorAll("button[data-alert-case]").forEach((button) => button.addEventListener("click", async () => {
    const alert = byId.get(button.dataset.alertCase);
    const kind = { domain: "domain", social_profile: "handle", application: "application" }[alert.target_type] || "auto";
    button.disabled = true;
    try {
      const check = await api(`/monitoring/targets/${alert.target_id}/checks/${alert.check_id}`);
      const created = await api("/cases", {
        method: "POST",
        body: JSON.stringify({
          title: `Monitoring alert #${alert.id}: ${alert.summary}`.slice(0, 255),
          target: alert.target,
          kind,
          note: `Created from monitoring alert #${alert.id}`,
          snapshot: { monitoring_check: check, monitoring_alert: alert },
        }),
      });
      button.textContent = `Case #${created.id}`;
      flash(`Case #${created.id} created from monitoring alert`);
    } catch (e) {
      button.disabled = false;
      flash(e.message, false);
    }
  }));
}

async function handleMonitoringAction(button) {
  const id = button.dataset.id, action = button.dataset.monAction;
  try {
    if (action === "pause" || action === "resume") {
      await api(`/monitoring/targets/${id}`, { method: "PATCH", body: JSON.stringify({ enabled: action === "resume" }) });
      flash(`Monitoring target ${action === "pause" ? "paused" : "resumed"}`);
    } else if (action === "remove") {
      await api(`/monitoring/targets/${id}`, { method: "DELETE" });
      flash("Monitoring target removed; history retained");
    } else if (action === "check") {
      button.disabled = true;
      const check = await api(`/monitoring/targets/${id}/check`, { method: "POST", body: "{}" });
      $("#mon-check-detail").innerHTML = `<h3>Check #${check.id} — ${stageBadge(check.status)}</h3><div class="kv"><div class="k">Started</div><div>${fmtDate(check.started_at)}</div><div class="k">Finished</div><div>${fmtDate(check.finished_at)}</div><div class="k">Providers</div><div class="mono">${esc(JSON.stringify(check.providers))}</div><div class="k">Error</div><div>${esc(check.error || "—")}</div></div><details><summary>Observed results and changes</summary><pre class="mono">${esc(JSON.stringify(check.result, null, 2))}</pre></details>`;
      flash(`Monitoring check finished: ${check.status}`, check.status === "completed");
    } else if (action === "history") {
      const checks = await api(`/monitoring/targets/${id}/checks`);
      $("#mon-check-detail").innerHTML = checks.length
        ? `<h3>Recent check history</h3><ul class="list">${checks.map((check) => `<li>Check #${check.id} — ${stageBadge(check.status)} · ${fmtDate(check.finished_at)}${check.error ? ` · ${esc(check.error)}` : ""}</li>`).join("")}</ul>`
        : "<div class='state'>No check attempts recorded.</div>";
    }
    loadMonitoring();
  } catch (e) { flash(e.message, false); }
  finally { button.disabled = false; }
}

$("#mon-create").addEventListener("click", async () => {
  try {
    const body = {
      target_type: $("#mon-type").value,
      target: $("#mon-target").value.trim(),
      interval_seconds: Number($("#mon-interval").value),
    };
    const brandId = $("#mon-brand").value.trim();
    if (brandId) body.brand_id = Number(brandId);
    const target = await api("/monitoring/targets", { method: "POST", body: JSON.stringify(body) });
    flash(`Monitoring target #${target.id} created; awaiting first successful check`, false);
    loadMonitoring();
  } catch (e) { flash(e.message, false); }
});
$("#mon-refresh").addEventListener("click", loadMonitoring);

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
    if (btn.dataset.view === "monitoring") loadMonitoring();
    if (btn.dataset.view === "reviews") loadReviews();
    if (btn.dataset.view === "evaluation") loadEvaluation();
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
    let html = `<div class="panel" style="margin-top:14px">
      <h3>Stored submission</h3>
      <div class="kv">
        <div class="k">Submission id</div><div class="mono">#${r.id}</div>
        <div class="k">Type</div><div>${esc(r.submission_type)}</div>
        <div class="k">Content hash</div><div class="mono">${esc(r.content_hash.slice(0, 24))}…</div>
        <div class="k">Stored at</div><div>${fmtDate(r.created_at)}</div>
      </div></div>`;
    if (r.submission_type === "app_listing") {
      try {
        const analysis = await api("/evidence/analyze", { method: "POST", body: JSON.stringify({
          target: r.content, kind: "application", input_type: "app_listing", analyzers: ["application"],
        }) });
        const result = analysis.results.find((item) => item.analyzer_type === "application");
        if (!result) throw new Error("Application analyzer returned no result");
        const metadata = result.observations.find((item) => item.kind === "store_listing_metadata");
        html += `<div class="panel" style="margin-top:14px"><h3>Listing analysis — ${stageBadge(result.status)}</h3>`;
        if (metadata) {
          html += `<div class="kv">${Object.entries(metadata.value).map(([key, value]) =>
            `<div class="k">${esc(key.replaceAll("_", " "))}</div><div>${esc(value)}</div>`).join("")}
            <div class="k">Source</div><div>${esc(metadata.source)} · retrieved ${fmtDate(metadata.retrieved_at)}</div></div>`;
        }
        if (result.indicators.length) html += `<ul class="list">${result.indicators.map((item) =>
          `<li>${esc(item.kind)} — ${esc(item.brand || "registered asset")} (${esc(item.verification || "heuristic")})</li>`).join("")}</ul>`;
        if (result.limitations.length) html += `<ul class="list">${result.limitations.map((item) => `<li class="muted">${esc(item)}</li>`).join("")}</ul>`;
        html += "</div>";
        flash(`Submission #${r.id} stored; app listing analysis ${result.status}`, result.status === "completed");
      } catch (e) {
        html += `<div class="state error">Stored, but listing analysis could not be completed: ${esc(e.message)}</div>`;
        flash(`Submission #${r.id} stored; analysis unavailable`, false);
      }
    } else {
      flash(`Submission #${r.id} stored`);
    }
    out.innerHTML = html;
  } catch (e) {
    out.innerHTML = `<div class='state error'>${esc(e.message)}</div>`;
  }
});

/* ---------- investigate ---------- */
$("#inv-btn").addEventListener("click", runPipeline);
async function runPipeline() {
  const target = $("#inv-target").value.trim();
  const candidateType = $("#inv-type").value;
  const out = $("#inv-result");
  if (!target) { flash("Enter a target first", false); return; }
  out.innerHTML = "<div class='state'>Running pipeline…</div>";
  const stage = {};
  const render = () => { out.innerHTML = renderInvestigation(target, stage); };
  const isHandle = /^@[A-Za-z0-9_.]{1,50}$/.test(target);
  const isApplication = candidateType === "app_listing";
  if (candidateType === "social_profile" && !isHandle) {
    flash("Enter a plain @handle; profile URL parsing needs a configured platform provider", false);
    return;
  }
  const evidenceRequest = isApplication
    ? { target, kind: "application", input_type: "app_listing", analyzers: ["application"] }
    : isHandle || candidateType === "social_profile"
    ? { target, kind: "handle", input_type: "social_profile", analyzers: ["brand_profile"] }
    : { target };
  const downstreamContext = isApplication ? { kind: "application" } :
    (isHandle || candidateType === "social_profile") ? { kind: "handle" } : {};

  // Application identity must come from the parsed listing evidence, not its store host.
  if (isApplication) {
    try { stage.evidence = { ok: true, data: await api("/evidence/analyze", { method: "POST", body: JSON.stringify(evidenceRequest) }) }; }
    catch (e) { stage.evidence = { ok: false, error: e.message }; }
    render();
  }

  // Step 1: run gate and evidence concurrently for URL/profile workflows.
  if (!isApplication) await Promise.all([
    (async () => {
      try { stage.gate = { ok: true, data: await api("/gate/evaluate", { method: "POST", body: JSON.stringify({ target }) }) }; }
      catch (e) { stage.gate = { ok: false, error: e.message }; }
      render();
    })(),
    (async () => {
      try { stage.evidence = { ok: true, data: await api("/evidence/analyze", { method: "POST", body: JSON.stringify(evidenceRequest) }) }; }
      catch (e) { stage.evidence = { ok: false, error: e.message }; }
      render();
    })(),
  ]);

  // Prefer usable evidence for the submitted identifier, so a handle never forwards
  // a failed URL parse to downstream services.
  const evidenceData = stage.evidence && stage.evidence.ok ? stage.evidence.data : null;
  const results = evidenceData && Array.isArray(evidenceData.results) ? evidenceData.results : [];
  const preferredAnalyzer = isApplication ? "application" : isHandle || candidateType === "social_profile" ? "brand_profile" : "url";
  const analysisPayload = results.find((r) => r.analyzer_type === preferredAnalyzer && ["completed", "partial"].includes(r.status)) ||
    results.find((r) => ["completed", "partial"].includes(r.status)) || null;

  // Step 2: Run Stage 7 rules with real Stage 5 analysis payload.
  if (isApplication) {
    try { stage.gate = { ok: true, data: await api("/gate/evaluate", { method: "POST", body: JSON.stringify({ target, kind: "application", analysis: analysisPayload }) }) }; }
    catch (e) { stage.gate = { ok: false, error: e.message }; }
    render();
  }
  try {
    const rulesBody = { target, ...downstreamContext, analysis: analysisPayload };
    stage.rules = { ok: true, data: await api("/rules/evaluate", { method: "POST", body: JSON.stringify(rulesBody) }) };
  } catch (e) {
    stage.rules = { ok: false, error: e.message };
  }
  render();

  // Step 3: Run Stage 11 risk scoring, Stage 12 grounded analysis, and Stage 9 investigation
  // concurrently, passing real Stage 5 evidence to each.
  const downstreamPayload = { target, ...downstreamContext, analysis: analysisPayload };
  await Promise.all([
    (async () => {
      try {
        stage.risk = { ok: true, data: await api("/risk/score", { method: "POST", body: JSON.stringify(downstreamPayload) }) };
      } catch (e) {
        stage.risk = { ok: false, error: e.message };
      }
      render();
    })(),
    (async () => {
      try {
        stage.rag = { ok: true, data: await api("/rag/analyze", { method: "POST", body: JSON.stringify(downstreamPayload) }) };
      } catch (e) {
        stage.rag = { ok: false, error: e.message };
      }
      render();
    })(),
    (async () => {
      try {
        stage.investigate = { ok: true, data: await api("/investigate", { method: "POST", body: JSON.stringify(downstreamPayload) }) };
      } catch (e) {
        stage.investigate = { ok: false, error: e.message };
      }
      render();
    })(),
  ]);
  // Keep the last investigation so it can be attached to a case.
  store.lastInvestigation = { target, stage };
  store.snapshots.push({ label: `${target} — ${new Date().toLocaleTimeString()}`, snapshot: buildSnapshot(stage) });
  refreshSnapshotOptions();
  const incompleteStages = Object.entries(stage).filter(([, result]) => hasIncompleteResult(result)).map(([name]) => name);
  if (incompleteStages.length) {
    flash(`Pipeline finished with incomplete or held stages: ${incompleteStages.join(", ")}`, false);
  } else {
    flash("Pipeline complete");
  }
}

function hasIncompleteResult(result) {
  if (!result.ok) return true;
  const data = result.data || {};
  const incompleteStatuses = ["partial", "failed", "failed_closed", "provider_unavailable", "no_evidence", "unavailable", "no_model", "model_unavailable", "routed_to_verification", "excluded_verified_official"];
  return incompleteStatuses.includes(data.status) ||
    ["verified_official", "unverified"].includes(data.outcome) ||
    (Array.isArray(data.errors) && data.errors.length > 0) ||
    (Array.isArray(data.limitations) && data.limitations.length > 0) ||
    (Array.isArray(data.summaries) && data.summaries.some((summary) => summary.status !== "completed"));
}

function buildSnapshot(stage) {
  const snap = {};
  for (const [k, v] of Object.entries(stage)) {
    snap[k] = v.ok
      ? { status: hasIncompleteResult(v) ? "partial" : "completed", data: v.data }
      : { status: "failed", error: v.error };
  }
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
      ${(data.input_quality || []).length ? `<div class="k">Evidence coverage</div><div class="mono" style="font-size:11.5px">${esc(data.input_quality.join(" | "))}</div>` : ""}
    </div>
    ${sigs ? `<h3>Contributing signals</h3><ul class="list">${sigs}</ul>` : ""}
    ${(imp.missing_data || []).length ? `<h3>Missing impact data</h3><ul class="list">${imp.missing_data.map((m) => `<li class="muted">${esc(m)}</li>`).join("")}</ul>` : ""}
    ${(data.limitations || []).length ? `<h3>Assessment notes &amp; limitations</h3><ul class="list">${data.limitations.map((l) => `<li class="muted" style="font-size:12px">${esc(l)}</li>`).join("")}</ul>` : ""}`;
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
      kind: $("#case-kind").value,
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

/* ---------- demo seeder (Stage 15) ---------- */
const seedBtn = $("#seed-demo-btn");
if (seedBtn) {
  seedBtn.addEventListener("click", async () => {
    seedBtn.disabled = true;
    seedBtn.textContent = "Seeding…";
    try {
      const res = await api("/demo/seed", { method: "POST" });
      flash(`Seeded demo data! Created ${res.brands_created} brand(s), ${res.cases_created} case(s), ${res.reviews_created} review(s).`);
      loadDashboard();
    } catch (e) {
      flash(`Seeding failed: ${e.message}`, false);
    } finally {
      seedBtn.disabled = false;
      seedBtn.textContent = "⚡ Seed Demo Data";
    }
  });
}

/* ---------- reviews & feedback (Stage 14) ---------- */
async function loadReviews() {
  const list = $("#reviews-list"), fSum = $("#feedback-summary");
  list.innerHTML = "<div class='state'>Loading…</div>";
  try {
    const [revs, fb] = await Promise.all([api("/review/history"), api("/feedback/labels")]);
    fSum.innerHTML = `Retrieved <b>${fb.count}</b> feedback labels (<b>${fb.usable_training_count}</b> with full ML feature vectors).`;
    if (!revs.length) {
      list.innerHTML = "<div class='state'>No human reviews recorded yet. Submit one above.</div>";
    } else {
      list.innerHTML = `<table>
        <thead><tr><th>#</th><th>Target</th><th>Verdict</th><th>Reason</th><th>Analyst</th><th>Date</th></tr></thead>
        <tbody>` + revs.map((r) => `<tr>
          <td>#${r.id}</td>
          <td class="mono">${esc(r.target)}</td>
          <td>${verdictBadge(r.verdict)}</td>
          <td>${esc(r.reason)}</td>
          <td><b>${esc(r.analyst)}</b></td>
          <td>${fmtDate(r.created_at)}</td>
        </tr>`).join("") + "</tbody></table>";
    }
  } catch (e) {
    list.innerHTML = `<div class='state error'>${esc(e.message)}</div>`;
  }
}

const revBtn = $("#rev-btn");
if (revBtn) {
  revBtn.addEventListener("click", async () => {
    const target = $("#rev-target").value.trim();
    const caseId = $("#rev-case-id").value.trim();
    const verdict = $("#rev-verdict").value;
    const reason = $("#rev-reason").value.trim();
    const analyst = $("#rev-analyst").value.trim() || "analyst";

    if (!reason || reason.length < 5) {
      flash("Mandatory reason must be at least 5 characters.", false);
      return;
    }
    revBtn.disabled = true;
    try {
      const payload = {
        verdict,
        reason,
        analyst,
      };
      if (caseId) payload.case_id = parseInt(caseId, 10);
      if (target) payload.target = target;
      await api("/review", { method: "POST", body: JSON.stringify(payload) });
      flash(`Recorded ${verdict} review verdict!`);
      $("#rev-reason").value = "";
      $("#rev-target").value = "";
      $("#rev-case-id").value = "";
      loadReviews();
    } catch (e) {
      flash(e.message, false);
    } finally {
      revBtn.disabled = false;
    }
  });
}

const retrainBtn = $("#retrain-btn");
if (retrainBtn) {
  retrainBtn.addEventListener("click", async () => {
    const resDiv = $("#retrain-result");
    resDiv.innerHTML = "<div class='state'>Triggering retraining…</div>";
    try {
      const fb = await api("/feedback/labels");
      const rows = [];
      fb.items.forEach((item) => {
        if (item.features) {
          rows.push({ features: item.features, label: item.label });
        }
      });
      const classCounts = [rows.filter((row) => row.label === 0).length, rows.filter((row) => row.label === 1).length];
      if (rows.length < 10 || Math.min(...classCounts) < 4) {
        throw new Error(`Insufficient real analyst labels: found ${rows.length} usable samples (${classCounts[0]} benign, ${classCounts[1]} malicious); need at least 10 samples and 4 per class.`);
      }
      const trainRes = await api("/ml/train", {
        method: "POST",
        body: JSON.stringify({ dataset: rows, random_state: 42 }),
      });
      resDiv.innerHTML = `<div class="flash ok" style="display:block;margin-top:8px;">Model trained (${esc(trainRes.model_version)})! Held-out ROC-AUC: <b>${trainRes.metrics.model_roc_auc ?? "n/a"}</b> vs Rules Baseline: <b>${trainRes.metrics.rules_baseline_roc_auc ?? "n/a"}</b></div>`;
    } catch (e) {
      resDiv.innerHTML = `<div class="flash err" style="display:block;margin-top:8px;">${esc(e.message)}</div>`;
    }
  });
}

/* ---------- evaluation (Stage 15) ---------- */
async function loadEvaluation() {
  // ready for benchmark trigger
}

const runBenchBtn = $("#run-bench-btn");
if (runBenchBtn) {
  runBenchBtn.addEventListener("click", async () => {
    const el = $("#bench-result");
    el.innerHTML = "<div class='state'>Running synthetic evaluation benchmark across 40 test samples…</div>";
    runBenchBtn.disabled = true;
    try {
      const res = await api("/evaluation/benchmark");
      const m = res.metrics;
      const dist = Object.entries(res.fired_rule_distribution).map(([r, c]) =>
        `<span class="tag"><b>${esc(r)}</b>: ${c}</span>`).join(" ");

      el.innerHTML = `
        <div class="cards">
          <div class="card"><div class="lbl">Samples</div><div class="num">${m.total_samples}</div></div>
          <div class="card"><div class="lbl">Accuracy</div><div class="num">${(m.accuracy * 100).toFixed(1)}%</div></div>
          <div class="card"><div class="lbl">Precision</div><div class="num">${(m.precision * 100).toFixed(1)}%</div></div>
          <div class="card"><div class="lbl">Recall</div><div class="num">${(m.recall * 100).toFixed(1)}%</div></div>
          <div class="card"><div class="lbl">F1 Score</div><div class="num">${(m.f1_score * 100).toFixed(1)}%</div></div>
          <div class="card"><div class="lbl">Avg Latency</div><div class="num">${m.avg_latency_ms} ms</div></div>
        </div>
        <div class="panel" style="margin-top:14px;">
          <h3>Confusion Matrix</h3>
          <div class="kv">
            <span class="k">True Positives / Negatives:</span><span>${m.true_positives} TP / ${m.true_negatives} TN</span>
            <span class="k">False Positives / Negatives:</span><span>${m.false_positives} FP / ${m.false_negatives} FN</span>
          </div>
          <h3>Fired Rule Distribution</h3>
          <div class="pill-row">${dist || "<span class='muted'>None</span>"}</div>
          <p class="muted" style="font-size:12px;margin-top:14px;"><b>Disclaimer:</b> ${esc(res.disclaimer)}</p>
        </div>
      `;
    } catch (e) {
      el.innerHTML = `<div class='state error'>${esc(e.message)}</div>`;
    } finally {
      runBenchBtn.disabled = false;
    }
  });
}

/* ---------- init ---------- */
loadDashboard();

