/* Deterministic summary over actual pipeline responses; no model-generated facts. */
(function attachInvestigationSummary(root) {
  function dataFor(stage, key) {
    const result = stage[key];
    return result && result.ok && result.data && typeof result.data === "object" ? result.data : null;
  }

  function unique(values) {
    return [...new Set(values.filter((value) => typeof value === "string" && value.trim()))];
  }

  function cite(item) {
    const citations = Array.isArray(item?.citations) ? item.citations : [];
    return citations.map((citation) => {
      const reference = citation.doc_id || citation.reference || citation.url || citation.source_reference;
      const locator = citation.locator || citation.section || citation.page;
      const source = citation.source_type;
      return [source, reference, locator].filter((part) => typeof part === "string" && part.trim()).join(" · ");
    }).filter(Boolean);
  }

  function buildInvestigationSummary(target, stage, candidateType = "auto") {
    const gateResult = dataFor(stage, "gate");
    const evidenceResult = dataFor(stage, "evidence");
    const rulesResult = dataFor(stage, "rules");
    const riskResult = dataFor(stage, "risk");
    const ragResult = dataFor(stage, "rag");
    const investigationResult = dataFor(stage, "investigate");
    const socialDiscovery = dataFor(stage, "social_discovery");
    const monitoring = dataFor(stage, "monitoring");
    const evidence = evidenceResult?.results || [];
    const displayValue = (value) => {
      const text = typeof value === "string" ? value
        : Array.isArray(value) ? value.join(", ")
          : value && typeof value === "object" ? JSON.stringify(value)
            : String(value ?? "observed");
      return text.length > 180 ? `${text.slice(0, 177)}…` : text;
    };
    const examined = [];
    for (const result of evidence) {
      const sources = (result.evidence || []).flatMap((item) => [
        item.provenance?.source,
        item.provenance?.method,
        item.source_reference?.kind,
      ]);
      for (const observation of result.observations || []) {
        sources.push(observation.source, observation.method);
      }
      const actualSources = unique(sources);
      examined.push(`${result.analyzer_type} (${result.status})${actualSources.length ? `: ${actualSources.join(", ")}` : ""}`);
    }
    for (const document of ragResult?.retrieved_documents || []) {
      const sourceLabel = document.source_type === "web_search"
        ? "unverified web-search snippet (page not fetched)"
        : `${document.source_type} document`;
      examined.push(`${sourceLabel} ${document.doc_id}`);
    }
    for (const hit of investigationResult?.evidence_hits || []) examined.push(`${hit.kind} ${hit.reference}`);
    for (const hit of investigationResult?.research_hits || []) examined.push(`${hit.source} ${hit.url}`);
    for (const candidate of socialDiscovery?.candidates || []) {
      examined.push(`${candidate.source} profile ${candidate.target} (${candidate.source_reference})`);
    }
    for (const item of monitoring?.observations || []) {
      examined.push(`${item.source} ${item.kind} ${item.key}`);
    }

    const gateOutcome = gateResult?.outcome || riskResult?.gate_decision?.outcome ||
      rulesResult?.gate_decision?.outcome || ragResult?.gate_decision?.outcome ||
      investigationResult?.gate_decision?.outcome || "unavailable";
    const gateWasEvaluated = Boolean(gateResult || riskResult?.gate_decision ||
      rulesResult?.gate_decision || ragResult?.gate_decision || investigationResult?.gate_decision);
    let gateReason = gateResult?.reason || riskResult?.gate_decision?.reason ||
      rulesResult?.gate_decision?.reason || ragResult?.gate_decision?.reason ||
      investigationResult?.gate_decision?.reason || "No gate decision was returned.";

    const findings = rulesResult?.findings || [];
    const observedIndicators = evidence.flatMap((result) => {
      const observationText = (item, label) => {
        const provenance = unique([item.source, item.method, item.provenance?.source, item.provenance?.method]);
        const source = provenance.length ? ` [${provenance.join(" / ")}]` : "";
        return `${result.analyzer_type || "analyzer"} · ${item.kind || label}${source}: ${displayValue(item.value)}`;
      };
      return [
        ...(result.indicators || []).map((item) => observationText(item, "Indicator")),
        ...(result.observations || []).filter((item) => item.kind !== "provider_status")
          .map((item) => observationText(item, "Observation")),
      ];
    });
    let ruleConclusion;
    if (!rulesResult || rulesResult.status === "failed_closed") {
      ruleConclusion = "Rules could not be evaluated; this is not a no-match result.";
    } else if (rulesResult.status === "excluded_verified_official") {
      ruleConclusion = "Rule evaluation was skipped because Stage 6 excluded a verified official asset.";
    } else if (rulesResult.status === "routed_to_verification") {
      ruleConclusion = "Rule evaluation was held for identity verification by Stage 6.";
    } else if (findings.length) {
      ruleConclusion = `${findings.length} security rule(s) matched: ${findings.map((item) => item.rule_id).join(", ")}.`;
    } else {
      const skipped = (rulesResult.skipped || []).length;
      ruleConclusion = skipped
        ? `No rule matched among evaluated rules; ${skipped} rule(s) could not be evaluated.`
        : "No rule matched. That does not establish that the candidate is safe.";
    }

    const mlRisk = riskResult?.detection_risk?.ml_risk;
    const mlConclusion = typeof mlRisk === "number"
      ? `An ML ranking score was available (${mlRisk}); it is not a calibrated probability.`
      : riskResult?.status === "scored"
        ? "No ML prediction was available; the model score was omitted."
        : `ML prediction was not available from the returned risk result${riskResult?.status ? ` (${riskResult.status})` : ""}.`;
    const score = riskResult?.overall_score;
    const scoreMeaning = typeof score === "number"
      ? `Overall risk/impact ranking: ${score}. ${riskResult.score_semantics || "This is a prioritization score, not a probability of maliciousness."}`
      : "No overall risk/impact score was returned; no score is inferred.";

    const acceptedRag = ragResult?.claims || [];
    const rejectedCount = (ragResult?.rejected_claims || []).length;
    const investigatorFindings = investigationResult?.findings || [];
    const citedClaims = acceptedRag.map((item) => ({
      text: item.text || item.claim || item.statement || "",
      kind: item.kind || item.claim_type || "cited claim",
      citations: cite(item),
    })).filter((item) => item.text);
    const recommendations = (ragResult?.recommended_next_actions || []).map((item) => {
      if (typeof item === "string") return { text: item, basis: "", citations: [] };
      return {
      text: item.text || item.action || item.recommendation || "",
        basis: item.basis || item.reason || "",
        citations: cite(item),
      };
    }).filter((item) => item.text);
    const investigatorItems = investigatorFindings.map((item) => ({
      text: item.finding || item.text || item.summary || "",
      citations: cite(item),
      source: item.source || item.source_reference || "",
    })).filter((item) => item.text);
    const ruleFindings = findings.map((item) => ({
      text: `${item.rule_id || "Security rule"}: ${item.title || item.reason || "matched"}${item.reason && item.title ? ` — ${item.reason}` : ""}`,
      severity: item.severity || "",
      evidence_refs: Array.isArray(item.evidence_refs) ? item.evidence_refs : [],
    }));
    let aiConclusion;
    if (acceptedRag.length || investigatorFindings.length || rejectedCount) {
      aiConclusion = `Grounded analysis returned ${acceptedRag.length} accepted/citation-validated item(s) and rejected ${rejectedCount} unsupported item(s); the investigator returned ${investigatorFindings.length} cited finding(s).`;
    } else if (["provider_unavailable", "no_evidence"].includes(ragResult?.status) ||
      investigationResult?.status === "provider_unavailable") {
      aiConclusion = "No supported AI claim was produced because a provider or usable evidence was unavailable.";
    } else {
      aiConclusion = "No supported AI claim or investigator finding was returned.";
    }

    const missing = [];
    for (const [stageName, result] of Object.entries(stage)) {
      if (result && result.ok === false && result.error) missing.push(`${stageName}: ${result.error}`);
      const data = result?.ok ? result.data : null;
      if (data?.status === "provider_unavailable") missing.push(`${stageName}: provider unavailable`);
      for (const error of data?.errors || []) missing.push(`${stageName}: ${error.message || error.stage || "provider error"}`);
    }
    for (const result of evidence) {
      for (const limitation of result.limitations || []) missing.push(`${result.analyzer_type}: ${limitation}`);
      for (const error of result.errors || []) missing.push(`${result.analyzer_type}: ${error.message || error.stage || "analysis error"}`);
      if (["unavailable", "failed"].includes(result.status)) missing.push(`${result.analyzer_type}: analyzer status ${result.status}`);
    }
    if (!evidence.length) missing.push("Stage 5 evidence results were unavailable.");
    for (const limitation of riskResult?.limitations || []) missing.push(`risk: ${limitation}`);
    for (const limitation of ragResult?.limitations || []) missing.push(`RAG: ${limitation}`);
    for (const limitation of investigationResult?.limitations || []) missing.push(`investigator: ${limitation}`);
    if (ragResult && !acceptedRag.length && !["provider_unavailable", "no_evidence"].includes(ragResult.status)) {
      missing.push("RAG returned no supported claims; the deterministic summary uses only returned evidence and findings.");
    }
    if (investigationResult && !investigatorFindings.length && investigationResult.status === "completed") {
      missing.push("Investigator returned no cited findings; this is not evidence that no threat exists.");
    }
    for (const failure of socialDiscovery?.failures || []) missing.push(`social provider ${failure.source}: ${failure.reason}`);
    if (socialDiscovery?.status === "inconclusive") missing.push("Social provider returned no matching profile; absence of a result is inconclusive.");
    if (!gateWasEvaluated) missing.push("Stage 6 gate decision was unavailable.");
    if (rulesResult) {
      for (const rule of rulesResult.skipped || []) missing.push(`rule ${rule.rule_id}: ${rule.reason}`);
    } else missing.push("Stage 7 rule result was unavailable.");
    const missingEvidence = unique(missing);

    let disposition = "inconclusive";
    if (gateOutcome === "verified_official") disposition = "excluded_official";
    else if (gateOutcome === "unverified") disposition = "verification_required";
    else if (findings.length) disposition = "signals_found";
    else if (gateWasEvaluated && (gateOutcome === "failed_closed" || gateOutcome === "unavailable")) {
      disposition = "gate_unavailable";
    }

    let nextStep;
    if (socialDiscovery?.status === "provider_unavailable") nextStep = "Configure an authorized social profile provider; current registry comparison did not retrieve this external profile.";
    else if (gateOutcome === "verified_official") nextStep = "Do not escalate this identity as an impersonator; Stage 6 matched a registered verified official asset.";
    else if (gateOutcome === "unverified") nextStep = "Route to an analyst to verify the ambiguous/unverified asset before threat classification.";
    else if (gateWasEvaluated && (gateOutcome === "failed_closed" || gateOutcome === "unavailable")) nextStep = "Retry after the Stage 6 gate is available; do not treat this as eligible or clean.";
    else if (missingEvidence.length) nextStep = "Obtain the missing provider/evidence data or perform manual review; current results are inconclusive.";
    else if (!findings.length) nextStep = "No rule-based threat signal was found; use analyst review or additional evidence if the case warrants it.";
    else nextStep = "Review the cited rule findings and source evidence before deciding whether to open or escalate a case.";

    if (monitoring) {
      const alerts = monitoring.alerts || (monitoring.alert ? [monitoring.alert] : []);
      gateReason = "not evaluated by the monitoring check; no Stage 6 gate decision was returned";
      ruleConclusion = "rules were not evaluated by this monitoring check";
      disposition = alerts.length ? "signals_found" : "inconclusive";
      for (const [provider, result] of Object.entries(monitoring.providers || {})) {
        if (result?.status && result.status !== "completed") {
          missingEvidence.push(`monitoring provider ${provider}: ${result.error || result.status}`);
        }
      }
      if (monitoring.error) missingEvidence.push(`monitoring check: ${monitoring.error}`);
      const monitorMl = "ML prediction was not run for this monitoring check.";
      const monitorScore = "No investigation risk score was calculated by this monitoring check.";
      const monitorAi = "Grounded AI and investigator analysis were not run by this monitoring check.";
      nextStep = alerts.length
        ? "Review the persisted new or changed evidence and confirm provider status before escalating."
        : "Review provider coverage and run a follow-up investigation if concern remains; no change alert is not proof of safety.";
      missingEvidence.push("Stage 6, security rules, risk scoring and grounded analysis were not run during monitoring.");
      return {
        candidate: target,
        candidate_type: candidateType,
        disposition,
        assessment: alerts.length
          ? `${alerts.length} new or changed monitoring finding(s) need review.`
          : "No change alert was recorded by this check. This is not proof of safety.",
        main_findings: unique(alerts.map((item) => item.summary || item.change_type)),
        stage_statuses: [`monitoring: ${monitoring.status || "unknown"}`],
        evidence_examined: unique(examined),
        gate: gateReason,
        rules: ruleConclusion,
        ml: monitorMl,
        risk_score: monitorScore,
        ai_analysis: monitorAi,
        missing_evidence: unique(missingEvidence),
        next_step: nextStep,
        risk_score_value: null,
        risk_classification: "",
        input_quality: [],
        evidence_coverage: [],
        rule_findings: [],
        cited_claims: [],
        recommendations: [],
        investigator_findings: [],
        analyzer_observations: [],
      };
    }

    return {
      candidate: target,
      candidate_type: candidateType,
      disposition,
      assessment: gateOutcome === "verified_official"
        ? "The submitted identity matched a registered verified official asset."
        : gateOutcome === "unverified"
          ? "The identity needs analyst verification before threat classification."
          : findings.length
            ? `${findings.length} rule-based signal(s) were found. Review their evidence before acting.`
            : "The available evidence is inconclusive; no finding here establishes that the candidate is safe.",
      main_findings: unique([
        ...findings.map((item) => `${item.rule_id || "Security rule"}: ${item.title || item.reason || "matched"}`),
        ...observedIndicators,
      ]).slice(0, 8),
      stage_statuses: ["evidence", "gate", "rules", "risk", "rag", "investigate"].map((key) => {
        const result = stage[key];
        if (!result) return `${key}: not run`;
        if (!result.ok) return `${key}: unavailable`;
        const data = result.data || {};
        const unavailable = ["unavailable", "provider_unavailable", "no_evidence", "no_model", "model_unavailable", "failed", "failed_closed"];
        const partial = ["partial", "routed_to_verification", "excluded_verified_official"];
        const nestedStatuses = key === "evidence" ? (data.results || []).map((item) => item.status) : [];
        const nestedUnavailable = nestedStatuses.filter((status) => unavailable.includes(status)).length;
        const isUnavailable = unavailable.includes(data.status) ||
          (nestedStatuses.length > 0 && nestedUnavailable === nestedStatuses.length);
        const isPartial = partial.includes(data.status) ||
          nestedStatuses.some((status) => partial.includes(status)) ||
          (nestedUnavailable > 0 && nestedUnavailable < nestedStatuses.length);
        const status = isUnavailable ? "unavailable"
          : isPartial || data.errors?.length || data.limitations?.length ? "partial"
            : "completed";
        return `${key}: ${status}`;
      }),
      evidence_examined: unique(examined),
      gate: `${gateOutcome}: ${gateReason}`,
      rules: ruleConclusion,
      ml: mlConclusion,
      risk_score: scoreMeaning,
      risk_score_value: typeof score === "number" ? score : null,
      risk_classification: riskResult?.classification || riskResult?.risk_classification || riskResult?.risk_level || "",
      input_quality: Array.isArray(riskResult?.input_quality) ? riskResult.input_quality : [],
      ai_analysis: aiConclusion,
      rule_findings: ruleFindings,
      analyzer_observations: unique(observedIndicators),
      cited_claims: citedClaims,
      recommendations,
      investigator_findings: investigatorItems,
      evidence_coverage: evidence.map((result) => `${result.analyzer_type}: ${result.status}`),
      missing_evidence: missingEvidence,
      next_step: nextStep,
    };
  }

  root.buildInvestigationSummary = buildInvestigationSummary;
  function showCompletionDialog(dialog, summaryMarkup) {
    if (!dialog) return false;
    const summary = dialog.querySelector("#inv-completion-summary");
    if (!summary) return false;
    summary.innerHTML = summaryMarkup;
    if (!dialog.open && typeof dialog.showModal === "function") dialog.showModal();
    return true;
  }
  root.showInvestigationCompletionDialog = showCompletionDialog;
  if (typeof module !== "undefined" && module.exports) module.exports = {
    buildInvestigationSummary,
    showInvestigationCompletionDialog: showCompletionDialog,
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
