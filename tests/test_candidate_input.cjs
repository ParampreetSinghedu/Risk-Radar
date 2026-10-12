const assert = require("node:assert/strict");
const { test } = require("node:test");
const { normalizeSocialHandle } = require("../src/risk_radar/static/candidate_input.js");

test("social handle accepts optional @ and valid characters", () => {
  assert.deepEqual(normalizeSocialHandle("pika"), { valid: true, normalized: "@pika", reason: null });
  assert.deepEqual(normalizeSocialHandle(" @pika.show_1 "), { valid: true, normalized: "@pika.show_1", reason: null });
});

test("social handle rejects free text and malformed separators", () => {
  assert.equal(normalizeSocialHandle("pika show").valid, false);
  assert.equal(normalizeSocialHandle("@@pika").valid, false);
  assert.equal(normalizeSocialHandle("@" ).valid, false);
  assert.equal(normalizeSocialHandle("a".repeat(51)).valid, false);
});
