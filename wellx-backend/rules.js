const crypto = require("crypto");
const { run, get, all } = require("./db");

const DEFAULT_RULES = [
  {
    rule_id: "RULE-METHANE-THRESHOLD",
    version: "1.0",
    conditions: [
      { field: "methane_ppm", operator: ">", value: 500 },
      { field: "confidence_score", operator: ">=", value: 0.9 },
      { field: "repeat_scan", operator: "==", value: true }
    ],
    outcome_on_pass: "ELIGIBLE_FOR_REVIEW"
  },
  {
    rule_id: "RULE-GEO-INTEGRITY",
    version: "1.0",
    conditions: [{ field: "geo_valid", operator: "==", value: true }],
    outcome_on_pass: "GEO_VALIDATED"
  }
];

function applyOperator(left, operator, right) {
  switch (operator) {
    case ">": return left > right;
    case "<": return left < right;
    case ">=": return left >= right;
    case "<=": return left <= right;
    case "==": return left === right;
    case "!=": return left !== right;
    default: throw new Error(`unsupported operator: ${operator}`);
  }
}

function buildState(payload) {
  return {
    state_id: `STATE-${Date.now()}`,
    well_id: payload.well_id || "UNKNOWN",
    timestamp: payload.timestamp || new Date().toISOString(),
    methane_ppm: payload.methane_ppm,
    confidence_score: payload.confidence_score ?? 1.0,
    repeat_scan: payload.repeat_scan ?? true,
    sensor_id: payload.sensor_id || null,
    geo_valid: payload.geo_valid ?? true,
    gps: payload.gps || null,
    status: "PENDING_RULE_EVALUATION"
  };
}

async function ensureDefaultRuleSet() {
  const existing = await get("SELECT id FROM rule_sets WHERE version = ?", ["1.0.0"]);
  if (existing) return;
  const now = new Date().toISOString();
  await run(
    "INSERT INTO rule_sets(version, rules_json, is_active, approval_status, submitted_by, approved_by, created_at_utc, approved_at_utc, created_by, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ["1.0.0", JSON.stringify(DEFAULT_RULES), 1, "APPROVED", "system", "system", now, now, "system", "Initial default rule set"]
  );
  await run(
    "INSERT INTO rule_set_history(rule_set_version, action_type, actor_id, details_json, created_at_utc) VALUES (?, ?, ?, ?, ?)",
    ["1.0.0", "created", "system", JSON.stringify({ reason: "bootstrap" }), now]
  );
}

async function listRuleSets() {
  return await all("SELECT id, version, is_active, approval_status, submitted_by, approved_by, created_at_utc, approved_at_utc, notes FROM rule_sets ORDER BY id DESC");
}

async function getActiveRuleSet() {
  await ensureDefaultRuleSet();
  const row = await get("SELECT * FROM rule_sets WHERE is_active = 1 AND approval_status = 'APPROVED' ORDER BY id DESC LIMIT 1");
  if (!row) throw new Error("no active approved rule set found");
  return {
    version: row.version,
    rules: JSON.parse(row.rules_json),
    notes: row.notes,
    created_at_utc: row.created_at_utc,
    created_by: row.created_by,
    approval_status: row.approval_status
  };
}

async function getRuleSetByVersion(version) {
  const row = await get("SELECT * FROM rule_sets WHERE version = ?", [version]);
  if (!row) return null;
  return {
    version: row.version,
    rules: JSON.parse(row.rules_json),
    is_active: !!row.is_active,
    notes: row.notes,
    created_at_utc: row.created_at_utc,
    created_by: row.created_by,
    approval_status: row.approval_status,
    submitted_by: row.submitted_by,
    approved_by: row.approved_by,
    approved_at_utc: row.approved_at_utc
  };
}

async function createRuleSetDraft({ version, rules, created_by = "admin", notes = "" }) {
  const now = new Date().toISOString();
  await run(
    "INSERT INTO rule_sets(version, rules_json, is_active, approval_status, submitted_by, approved_by, created_at_utc, approved_at_utc, created_by, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [version, JSON.stringify(rules), 0, "PENDING_APPROVAL", created_by, null, now, null, created_by, notes]
  );
  await run(
    "INSERT INTO rule_set_history(rule_set_version, action_type, actor_id, details_json, created_at_utc) VALUES (?, ?, ?, ?, ?)",
    [version, "submitted_for_approval", created_by, JSON.stringify({ notes, rule_count: rules.length }), now]
  );
  return getRuleSetByVersion(version);
}

async function approveRuleSet(version, actor_id = "approver") {
  const now = new Date().toISOString();
  await run("UPDATE rule_sets SET approval_status = 'APPROVED', approved_by = ?, approved_at_utc = ? WHERE version = ?", [actor_id, now, version]);
  await run(
    "INSERT INTO rule_set_history(rule_set_version, action_type, actor_id, details_json, created_at_utc) VALUES (?, ?, ?, ?, ?)",
    [version, "approved", actor_id, JSON.stringify({ approved: true }), now]
  );
  return getRuleSetByVersion(version);
}

async function rejectRuleSet(version, actor_id = "approver", reason = "") {
  const now = new Date().toISOString();
  await run("UPDATE rule_sets SET approval_status = 'REJECTED', is_active = 0 WHERE version = ?", [version]);
  await run(
    "INSERT INTO rule_set_history(rule_set_version, action_type, actor_id, details_json, created_at_utc) VALUES (?, ?, ?, ?, ?)",
    [version, "rejected", actor_id, JSON.stringify({ reason }), now]
  );
  return getRuleSetByVersion(version);
}

async function activateRuleSet(version, actor_id = "approver") {
  const now = new Date().toISOString();
  const row = await get("SELECT approval_status FROM rule_sets WHERE version = ?", [version]);
  if (!row) throw new Error("rule set not found");
  if (row.approval_status !== "APPROVED") throw new Error("only approved rule sets can be activated");
  await run("UPDATE rule_sets SET is_active = 0");
  await run("UPDATE rule_sets SET is_active = 1 WHERE version = ?", [version]);
  await run(
    "INSERT INTO rule_set_history(rule_set_version, action_type, actor_id, details_json, created_at_utc) VALUES (?, ?, ?, ?, ?)",
    [version, "activated", actor_id, JSON.stringify({ activated: true }), now]
  );
  return getRuleSetByVersion(version);
}

async function listPendingApprovals() {
  return await all("SELECT id, version, submitted_by, created_at_utc, notes FROM rule_sets WHERE approval_status = 'PENDING_APPROVAL' ORDER BY id DESC");
}

function evaluateRulesWithRuleSet(state, ruleSet) {
  const rules = ruleSet.rules;
  const rule_results = [];
  const evaluation_trace = [];

  for (const rule of rules) {
    let passed = true;
    for (const cond of rule.conditions) {
      const left = state[cond.field];
      const result = applyOperator(left, cond.operator, cond.value);
      evaluation_trace.push(`${cond.field} ${cond.operator} ${JSON.stringify(cond.value)} -> ${result ? "TRUE" : "FALSE"}`);
      if (!result) passed = false;
    }
    rule_results.push({ rule_id: rule.rule_id, version: rule.version, result: passed ? "PASS" : "FAIL", outcome_on_pass: rule.outcome_on_pass });
  }

  const anyFail = rule_results.some(r => r.result === "FAIL");
  const allPass = rule_results.every(r => r.result === "PASS");
  let final_outcome = "MANUAL_REVIEW_REQUIRED";
  let status = "MANUAL_REVIEW_REQUIRED";
  if (allPass) {
    final_outcome = "ELIGIBLE_FOR_REVIEW";
    status = "RULES_PASSED";
  } else if (anyFail) {
    final_outcome = "REJECTED";
    status = "RULES_FAILED";
  }

  const normalized = {
    state,
    rule_set_version: ruleSet.version,
    rules_applied: rules.map(r => ({ rule_id: r.rule_id, version: r.version, conditions: r.conditions, outcome_on_pass: r.outcome_on_pass })),
    rule_results,
    final_outcome,
    status,
    evaluation_trace,
    evaluated_at: new Date().toISOString()
  };

  const decision_hash = crypto.createHash("sha256").update(JSON.stringify(normalized)).digest("hex");
  return { ...normalized, decision_hash };
}

module.exports = {
  DEFAULT_RULES,
  buildState,
  ensureDefaultRuleSet,
  listRuleSets,
  listPendingApprovals,
  getActiveRuleSet,
  getRuleSetByVersion,
  createRuleSetDraft,
  approveRuleSet,
  rejectRuleSet,
  activateRuleSet,
  evaluateRulesWithRuleSet
};
