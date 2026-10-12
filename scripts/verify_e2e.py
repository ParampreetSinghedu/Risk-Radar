"""Live end-to-end verification script for Risk Radar API and Dashboard."""

import httpx

client = httpx.Client(base_url="http://127.0.0.1:8000", timeout=10.0)

# 1. Health
h = client.get("/api/v1/health").json()
print("1. Health Endpoint:", h)
assert h == {"status": "ok"}

# 2. Frontend root
index = client.get("/")
print("2. Dashboard index.html Status:", index.status_code, f"({len(index.text)} bytes)")
assert index.status_code == 200
assert "Risk Radar" in index.text

# 3. Seed demo data
s = client.post("/api/v1/demo/seed").json()
print(
    "3. Demo Seeder:",
    f"brands={s['brands_created']}, cases={s['cases_created']}, reviews={s['reviews_created']}",
)
assert s["is_synthetic"] is True

# 4. Dashboard summary
dash = client.get("/api/v1/dashboard").json()
print(
    "4. Dashboard Metrics:",
    f"total_cases={dash['total_cases']}, open={dash['open_cases']}, "
    f"in_review={dash['in_review_cases']}, closed={dash['closed_cases']}",
)
assert dash["total_cases"] >= 3

# 5. Gate evaluation
gate_official = client.post(
    "/api/v1/gate/evaluate", json={"target": "https://paypal.com/signin"}
).json()
print(
    "5. Gate Official Evaluation:",
    f"outcome={gate_official['outcome']}, alert_eligible={gate_official['alert_eligible']}",
)
assert gate_official["outcome"] == "verified_official"
assert gate_official["alert_eligible"] is False

gate_phish = client.post(
    "/api/v1/gate/evaluate", json={"target": "https://paypa1-security-update.com/login"}
).json()
print(
    "6. Gate Phishing Evaluation:",
    f"outcome={gate_phish['outcome']}, alert_eligible={gate_phish['alert_eligible']}",
)
assert gate_phish["outcome"] == "not_matched"
assert gate_phish["alert_eligible"] is True

# 7. Rules evaluation
rules = client.post(
    "/api/v1/rules/evaluate", json={"target": "https://paypal-security-update.com/login"}
).json()
findings = [f["rule_id"] for f in rules["findings"]]
print("7. Rules Fired:", findings)
assert len(findings) >= 1

# 8. Risk scoring
risk = client.post(
    "/api/v1/risk/score", json={"target": "https://paypal-security-update.com/login"}
).json()
print(
    "8. Risk Score:",
    f"overall_score={risk['overall_score']}, status={risk['status']}",
)
assert risk["status"] == "scored"
assert risk["overall_score"] is not None

# 9. Human review & feedback
rev = client.post(
    "/api/v1/review",
    json={
        "target": "https://paypa1-security-update.com/login",
        "verdict": "malicious",
        "reason": "Live E2E verified typosquat targeting official PayPal users.",
        "analyst": "e2e_tester",
    },
).json()
print("9. Human Review Recorded:", f"id=#{rev['id']}, verdict={rev['verdict']}")

# 10. Feedback labels
fb = client.get("/api/v1/feedback/labels").json()
print(
    "10. Feedback Labels:",
    f"count={fb['count']}, usable={fb['usable_training_count']}",
)
assert fb["count"] >= 1

# 11. Evaluation benchmark
bench = client.get("/api/v1/evaluation/benchmark?sample_limit=10").json()
bm = bench["metrics"]
print(
    "11. Evaluation Benchmark (Stage 15):",
    f"samples={bm['total_samples']}, accuracy={bm['accuracy']}, "
    f"precision={bm['precision']}, recall={bm['recall']}, f1={bm['f1_score']}",
)
assert bm["total_samples"] == 10

print("\nSUCCESS: All 11 live HTTP API & frontend dashboard verification checks passed!")
