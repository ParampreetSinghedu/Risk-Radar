const assert = require("node:assert/strict");
const { test } = require("node:test");
const { buildInvestigationSummary } = require("../src/risk_radar/static/investigation_summary.js");

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
