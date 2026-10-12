/* Small deterministic input validators shared by the investigation UI and tests. */
(function attachCandidateInput(root) {
  function normalizeSocialHandle(value) {
    const raw = String(value ?? "").trim();
    const handle = raw.startsWith("@") ? raw.slice(1) : raw;
    if (!/^[A-Za-z0-9_.]{1,50}$/.test(handle)) {
      return { valid: false, normalized: null, reason: "Use 1–50 letters, numbers, dots or underscores, with an optional @." };
    }
    return { valid: true, normalized: `@${handle}`, reason: null };
  }

  root.normalizeSocialHandle = normalizeSocialHandle;
  if (typeof module !== "undefined" && module.exports) module.exports = { normalizeSocialHandle };
})(typeof globalThis !== "undefined" ? globalThis : this);
