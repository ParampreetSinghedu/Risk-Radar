const assert = require("node:assert/strict");
const { test } = require("node:test");
const { buildInvestigationSummary, showInvestigationCompletionDialog } = require("../src/risk_radar/static/investigation_summary.js");

test("summary uses actual gate, rules, ML and unavailable-provider results", () => {
  const summary = buildInvestigationSummary("iron man", {
    gate: { ok: true, data: { outcome: "not_matched", reason: "no official asset matched" } },
    evidence: { ok: true, data: { results: [{ analyzer_type: "brand_profile", status: "unavailable", limitations: ["No brands configured"] }] } },
    rules: { ok: true, data: { status: "evaluated", findings: [], skipped: [{ rule_id: "similarity", reason: "missing evidence" }] } },
    risk: { ok: true, data: { status: "scored", overall_score: 0.1, detection_risk: { ml_risk: null } } },
    rag: { ok: true, data: { status: "provider_unavailable", claims: [], rejected_claims: [], limitations: ["provider unavailable"] } },
    investigate: { ok: true, data: { status: "provider_unavailable", findings: [], limitations: ["source unavailable"] } },
  }, "name");
  assert.equal(summary.candidate, "iron man");
  assert.match(summary.rules, /could not be evaluated/);
  assert.match(summary.ml, /No ML prediction was available/);
  assert.match(summary.ai_analysis, /provider or usable evidence was unavailable/);
  assert.equal(summary.disposition, "inconclusive");
  assert.match(summary.next_step, /missing provider/);
  assert.match(summary.assessment, /inconclusive/);
  assert.ok(summary.stage_statuses.some((status) => status === "evidence: unavailable"));
  assert.ok(summary.stage_statuses.some((status) => status === "rag: unavailable"));
  assert.ok(summary.missing_evidence.some((item) => item.includes("provider unavailable")));
});

test("summary presents observed evidence and matched rules without implying probability or safety", () => {
  const summary = buildInvestigationSummary("lookalike.example", {
    evidence: { ok: true, data: { results: [{
      analyzer_type: "url", status: "completed",
      observations: [{ kind: "embedded_urls", value: ["https://lookalike.example/login"] }],
    }] } },
    gate: { ok: true, data: { outcome: "not_matched", reason: "no official asset matched" } },
    rules: { ok: true, data: { status: "evaluated", findings: [{
      rule_id: "lookalike_domain", title: "Domain resembles registered brand", reason: "similarity signal",
    }], skipped: [] } },
    risk: { ok: true, data: { status: "scored", overall_score: 0.72 } },
  }, "domain");
  assert.match(summary.assessment, /1 rule-based signal/);
  assert.ok(summary.main_findings.some((finding) => finding.includes("lookalike_domain")));
  assert.ok(summary.main_findings.some((finding) => finding.includes("https://lookalike.example/login")));
  assert.match(summary.risk_score, /not a probability/);
  assert.ok(summary.stage_statuses.some((status) => status === "investigate: not run"));
});

test("summary keeps provider state out of main findings and bounds long observations", () => {
  const summary = buildInvestigationSummary("candidate.example", {
    evidence: { ok: true, data: { results: [{
      analyzer_type: "image", status: "partial",
      observations: [
        { kind: "provider_status", value: { provider: "vision", status: "unavailable" } },
        { kind: "ocr_text", value: "visible login text ".repeat(30) },
      ],
      limitations: ["vision provider unavailable"],
    }] } },
  });
  assert.ok(!summary.main_findings.some((finding) => finding.includes("provider_status")));
  assert.ok(summary.main_findings.some((finding) => finding.length <= 220));
  assert.ok(summary.missing_evidence.some((item) => item.includes("vision provider unavailable")));
});

test("verified official gate is distinct from an eligible unmatched candidate", () => {
  const official = buildInvestigationSummary("brand.example", {
    gate: { ok: true, data: { outcome: "verified_official", reason: "exact registered asset" } },
  });
  assert.equal(official.disposition, "excluded_official");
  assert.match(official.next_step, /Do not escalate/);

  const unmatched = buildInvestigationSummary("other.example", {
    gate: { ok: true, data: { outcome: "not_matched", reason: "no match" } },
    rules: { ok: true, data: { status: "evaluated", findings: [], skipped: [] } },
  });
  assert.equal(unmatched.disposition, "inconclusive");
  assert.match(unmatched.rules, /No rule matched/);
});

test("summary reports rejected claims rather than inventing supported analysis", () => {
  const summary = buildInvestigationSummary("candidate", {
    rag: { ok: true, data: { status: "partial", claims: [], rejected_claims: [{ reason: "uncited" }] } },
  });
  assert.match(summary.ai_analysis, /0 accepted\/citation-validated item\(s\) and rejected 1/);
});

test("monitoring summary does not claim that unrun investigation stages were completed", () => {
  const summary = buildInvestigationSummary("acme.example", {
    monitoring: { ok: true, data: {
      status: "completed",
      providers: { social: { status: "unavailable", error: "no provider" } },
      observations: [{ source: "fixture", kind: "discovered_profile", key: "candidate-1" }],
      alert: { id: 4, change_type: "new" },
    } },
  }, "monitoring");
  assert.equal(summary.disposition, "signals_found");
  assert.match(summary.gate, /not evaluated/);
  assert.match(summary.rules, /not evaluated/);
  assert.match(summary.ml, /not run/);
  assert.match(summary.next_step, /Review the persisted/);
  assert.ok(summary.missing_evidence.some((item) => item.includes("provider social")));
  assert.ok(summary.missing_evidence.some((item) => item.includes("no provider")));
});

test("image and unavailable social discovery remain explicit and inconclusive", () => {
  const imageSummary = buildInvestigationSummary("brand.example", {
    evidence: { ok: true, data: { results: [{
      analyzer_type: "image", status: "completed",
      observations: [{ kind: "embedded_urls", value: ["https://lookalike.example"], method: "regex_url_extraction" }],
      evidence: [{ evidence_type: "ocr", provenance: { method: "tesseract" } }],
    }] } },
    rules: { ok: true, data: { status: "evaluated", findings: [], skipped: [] } },
  }, "domain");
  assert.equal(imageSummary.disposition, "inconclusive");
  assert.ok(imageSummary.evidence_examined.some((item) => item.includes("tesseract")));
  assert.match(imageSummary.next_step, /inconclusive/);

  const socialSummary = buildInvestigationSummary("@pika", {
    social_discovery: { ok: true, data: {
      status: "provider_unavailable", candidates: [],
      failures: [{ source: "social", reason: "no authorized provider" }],
    } },
  }, "social_profile");
  assert.equal(socialSummary.disposition, "inconclusive");
  assert.match(socialSummary.next_step, /Configure an authorized social profile provider/);
});

test("grounded summary distinguishes search snippets from retrieved pages", () => {
  const summary = buildInvestigationSummary("candidate.example", {
    rag: { ok: true, data: { status: "provider_unavailable", retrieved_documents: [{
      source_type: "web_search", doc_id: "web_search:abc", provenance: {
        content_kind: "search_snippet", page_content_retrieved: false,
      },
    }] } },
  }, "domain");
  assert.ok(summary.evidence_examined.some((item) => item.includes("unverified web-search snippet")));
  assert.ok(summary.evidence_examined.some((item) => item.includes("page not fetched")));
});

test("summary preserves cited RAG claims, recommendations, investigator findings, and provenance", () => {
  const summary = buildInvestigationSummary("candidate.example", {
    rag: { ok: true, data: {
      status: "partial",
      claims: [{ kind: "observed_fact", text: "The page requests account credentials.", citations: [{ source_type: "web_search", doc_id: "web:42", locator: "snippet" }] }],
      recommended_next_actions: [{ kind: "recommendation", text: "Review the destination manually.", basis: "The snippet references a sign-in form.", citations: [{ doc_id: "web:42" }] }],
      limitations: ["Search snippet only; page content was not fetched."],
    } },
    investigate: { ok: true, data: {
      status: "completed",
      findings: [{ finding: "A matching page title was observed.", citations: [{ source_type: "web", reference: "https://source.example/page", locator: "title" }] }],
    } },
  });
  assert.deepEqual(summary.cited_claims, [{
    text: "The page requests account credentials.", kind: "observed_fact", citations: ["web_search · web:42 · snippet"],
  }]);
  assert.equal(summary.recommendations[0].text, "Review the destination manually.");
  assert.equal(summary.recommendations[0].basis, "The snippet references a sign-in form.");
  assert.equal(summary.investigator_findings[0].text, "A matching page title was observed.");
  assert.deepEqual(summary.investigator_findings[0].citations, ["web · https://source.example/page · title"]);
  assert.ok(summary.missing_evidence.some((item) => item.includes("page content was not fetched")));
});

test("missing scores and providers remain explicit, with coverage separate from risk", () => {
  const summary = buildInvestigationSummary("candidate.example", {
    evidence: { ok: true, data: { results: [{ analyzer_type: "url", status: "partial" }] } },
    risk: { ok: true, data: { status: "partial", overall_score: null, limitations: ["insufficient input"] } },
    rag: { ok: false, error: "provider timeout" },
    investigate: { ok: true, data: { status: "provider_unavailable", findings: [] } },
  });
  assert.equal(summary.risk_score_value, null);
  assert.match(summary.risk_score, /No overall.*score was returned/);
  assert.deepEqual(summary.evidence_coverage, ["url: partial"]);
  assert.ok(summary.missing_evidence.some((item) => item.includes("rag: provider timeout")));
  assert.ok(summary.missing_evidence.some((item) => item.includes("insufficient input")));
  assert.deepEqual(summary.cited_claims, []);
  assert.deepEqual(summary.recommendations, []);
  assert.deepEqual(summary.investigator_findings, []);
});

test("empty and partial AI responses use a deterministic evidence-only fallback", () => {
  const summary = buildInvestigationSummary("candidate.example", {
    evidence: { ok: true, data: { results: [{ analyzer_type: "url", status: "completed", observations: [{ kind: "title", value: "Example sign in" }] }] } },
    rag: { ok: true, data: { status: "no_evidence", claims: [], recommended_next_actions: [], limitations: ["no retrieved evidence"] } },
    investigate: { ok: true, data: { status: "partial", findings: [], limitations: ["source query failed"] } },
  });
  assert.ok(summary.analyzer_observations.includes("url · title: Example sign in"));
  assert.match(summary.ai_analysis, /No supported AI claim/);
  assert.ok(summary.missing_evidence.some((item) => item.includes("no retrieved evidence")));
  assert.ok(summary.missing_evidence.some((item) => item.includes("source query failed")));
});

test("completion dialog shows a settled summary once and does not remove the inline summary", () => {
  let opened = 0;
  const modalSummary = { innerHTML: "" };
  const dialog = {
    open: false,
    querySelector: (selector) => selector === "#inv-completion-summary" ? modalSummary : null,
    showModal() { opened += 1; this.open = true; },
  };
  const inline = { innerHTML: "<p>Final deterministic summary</p>" };
  assert.equal(showInvestigationCompletionDialog(dialog, inline.innerHTML), true);
  assert.equal(showInvestigationCompletionDialog(dialog, inline.innerHTML), true);
  assert.equal(opened, 1);
  assert.equal(modalSummary.innerHTML, inline.innerHTML);
  dialog.open = false; // Simulate closing the modal; the inline result remains.
  assert.equal(inline.innerHTML, "<p>Final deterministic summary</p>");
});
