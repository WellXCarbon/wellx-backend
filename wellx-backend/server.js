const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const { anchorToXRPL, getWalletStatus } = require("./xrpl");
const { ensureBootstrapAdmin, authenticateUser, signToken, requireAuth, requireRole } = require("./auth");
const {
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
} = require("./rules");
const { initDb, run, get, all } = require("./db");
const { logAudit } = require("./audit");

const app = express();
const PORT = process.env.PORT || 3000;
const DEMO_API_KEY = process.env.API_KEY || process.env.DEMO_API_KEY || "";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function utcNow() {
  return new Date().toISOString();
}

function sha256(data) {
  return crypto.createHash("sha256").update(JSON.stringify(data)).digest("hex");
}

function requireApiKey(req, res, next) {
  if (!DEMO_API_KEY) return next();
  const given = req.header("x-api-key");
  if (given !== DEMO_API_KEY) {
    return res.status(401).json({ ok: false, error: "invalid api key" });
  }
  next();
}

function buildMptAsset(record) {
  return {
    asset_id: record.well_id,
    decision_hash: record.decision_hash,
    rule_version: record.rule_set_version,
    verification_status: record.final_outcome,
    xrpl_anchor_tx: record.xrpl_tx_hash,
    issued_at_utc: utcNow(),
    issuer: "WellX Carbon Intelligence",
    proof_type: "deterministic_mrv",
    token_class: "environmental_asset"
  };
}

async function issueMPT(asset) {
  const syntheticId = `MPT-${asset.asset_id}-${Date.now()}`;
  const syntheticTx = `mpt_tx_${Date.now()}_${Math.floor(Math.random() * 100000)}`;

  return {
    mptAssetId: syntheticId,
    txHash: syntheticTx,
    issuedAt: utcNow(),
    asset
  };
}

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await authenticateUser(email, password);
    if (!user) {
      return res.status(401).json({ ok: false, error: "invalid credentials" });
    }
    const token = signToken(user);
    res.json({
      ok: true,
      token,
      user: { id: user.id, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "wellx-mvp-v1.6",
    env: process.env.NODE_ENV || "development"
  });
});

app.get("/api/rules", requireApiKey, requireAuth, async (req, res) => {
  try {
    const active = await getActiveRuleSet();
    const sets = await listRuleSets();
    res.json({ ok: true, active_rule_set: active, rule_sets: sets });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/rules/pending", requireApiKey, requireAuth, requireRole("approver"), async (req, res) => {
  try {
    res.json({ ok: true, pending: await listPendingApprovals() });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/rules/:version", requireApiKey, requireAuth, async (req, res) => {
  try {
    const rs = await getRuleSetByVersion(req.params.version);
    if (!rs) {
      return res.status(404).json({ ok: false, error: "rule set not found" });
    }
    res.json({ ok: true, rule_set: rs });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/rules", requireApiKey, requireAuth, requireRole("admin", "editor"), async (req, res) => {
  try {
    const { version, rules, notes } = req.body;
    if (!version || !Array.isArray(rules) || !rules.length) {
      return res.status(400).json({
        ok: false,
        error: "version and non-empty rules array required"
      });
    }
    const created = await createRuleSetDraft({
      version,
      rules,
      created_by: req.user.email,
      notes: notes || ""
    });
    res.json({ ok: true, rule_set: created });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/rules/:version/approve", requireApiKey, requireAuth, requireRole("approver"), async (req, res) => {
  try {
    const approved = await approveRuleSet(req.params.version, req.user.email);
    res.json({ ok: true, rule_set: approved });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/rules/:version/reject", requireApiKey, requireAuth, requireRole("approver"), async (req, res) => {
  try {
    const rejected = await rejectRuleSet(
      req.params.version,
      req.user.email,
      (req.body && req.body.reason) || ""
    );
    res.json({ ok: true, rule_set: rejected });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/rules/:version/activate", requireApiKey, requireAuth, requireRole("approver"), async (req, res) => {
  try {
    const activated = await activateRuleSet(req.params.version, req.user.email);
    res.json({ ok: true, rule_set: activated });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/evaluate", requireApiKey, requireAuth, async (req, res) => {
  try {
    const state = buildState(req.body.payload || req.body);
    const ruleSet = req.body.rule_set_version
      ? await getRuleSetByVersion(req.body.rule_set_version)
      : await getActiveRuleSet();

    if (!ruleSet) {
      return res.status(404).json({ ok: false, error: "rule set not found" });
    }

    const evaluation = evaluateRulesWithRuleSet(state, ruleSet);
    res.json({ ok: true, evaluation });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/wallet-status", requireApiKey, async (req, res) => {
  try {
    res.json({ ok: true, wallet: await getWalletStatus() });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/process", requireApiKey, async (req, res) => {
  try {
    const payload = req.body;
    const wellId = payload.well_id || "UNKNOWN";
    const hash = sha256(payload);

    const insert = await run(
      "INSERT INTO records (well_id, payload_json, sha256_hash, status, created_at_utc) VALUES (?, ?, ?, ?, ?)",
      [wellId, JSON.stringify(payload), hash, "PROCESSING", utcNow()]
    );

    const recordId = insert.lastID;

    await run(
      "INSERT INTO events (record_id, event_type, message, created_at_utc) VALUES (?, ?, ?, ?)",
      [recordId, "dataset_uploaded", "Dataset uploaded and hashed", utcNow()]
    );

    const state = buildState(payload);
    const activeRuleSet = await getActiveRuleSet();
    const evaluation = evaluateRulesWithRuleSet(state, activeRuleSet);

    await run(
      "INSERT INTO rule_evaluations (record_id, state_json, rule_results_json, evaluation_trace_json, final_outcome, decision_hash, rule_set_version, created_at_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [
        recordId,
        JSON.stringify(evaluation.state),
        JSON.stringify(evaluation.rule_results),
        JSON.stringify(evaluation.evaluation_trace),
        evaluation.final_outcome,
        evaluation.decision_hash,
        evaluation.rule_set_version,
        utcNow()
      ]
    );

    await run(
      "INSERT INTO events (record_id, event_type, message, created_at_utc) VALUES (?, ?, ?, ?)",
      [recordId, "rules_evaluated", `Outcome: ${evaluation.final_outcome}`, utcNow()]
    );

    const existingRecord = await get(
      "SELECT xrpl_tx_hash FROM records WHERE id = ?",
      [recordId]
    );

    let xrpl_tx_hash = null;
    let xrpl_explorer_url = null;
    let wallet_address = null;
    let xrpl_anchor_error = null;
    let xrpl_anchor_status = "anchor_skipped";

    if (existingRecord && existingRecord.xrpl_tx_hash) {
      xrpl_anchor_status = "anchor_skipped";
      xrpl_tx_hash = existingRecord.xrpl_tx_hash || null;
    } else {
      const xrplPayload = {
        decision_hash: evaluation.decision_hash,
        rule_version: evaluation.rule_set_version,
        outcome: evaluation.final_outcome,
        nonce: crypto.randomUUID()
      };

      try {
        const xrpl = await anchorToXRPL(xrplPayload);

        xrpl_tx_hash = xrpl?.txHash || null;
        xrpl_explorer_url = xrpl?.explorerUrl || null;
        wallet_address = xrpl?.walletAddress || null;
        xrpl_anchor_status = "anchored";

        const finalStatus =
          evaluation.final_outcome === "ELIGIBLE_FOR_REVIEW"
            ? "ANCHORED_ELIGIBLE"
            : "ANCHORED_REJECTED";

        await run(
          "UPDATE records SET xrpl_tx_hash = ?, xrpl_explorer_url = ?, status = ? WHERE id = ?",
          [xrpl_tx_hash, xrpl_explorer_url, finalStatus, recordId]
        );

        await run(
          "INSERT INTO events (record_id, event_type, message, created_at_utc) VALUES (?, ?, ?, ?)",
          [
            recordId,
            "xrpl_anchored",
            JSON.stringify({
              txHash: xrpl_tx_hash,
              explorerUrl: xrpl_explorer_url,
              walletAddress: wallet_address,
              payload: xrplPayload
            }),
            utcNow()
          ]
        );
      } catch (err) {
        xrpl_anchor_error = err.message;
        xrpl_anchor_status = "anchor_failed";

        const finalStatus =
          evaluation.final_outcome === "ELIGIBLE_FOR_REVIEW"
            ? "ELIGIBLE_PENDING_ANCHOR"
            : "REJECTED_PENDING_ANCHOR";

        await run(
          "UPDATE records SET status = ? WHERE id = ?",
          [finalStatus, recordId]
        );

        await run(
          "INSERT INTO events (record_id, event_type, message, created_at_utc) VALUES (?, ?, ?, ?)",
          [recordId, "xrpl_anchor_failed", `XRPL anchor failed: ${xrpl_anchor_error}`, utcNow()]
        );

        console.error("XRPL anchor failed:", xrpl_anchor_error);
      }
    }

    const tokenization_ready =
      evaluation.final_outcome === "ELIGIBLE_FOR_REVIEW" &&
      xrpl_anchor_status === "anchored";

    const mpt_status = tokenization_ready ? "ready_for_issuance" : "not_ready";

    res.json({
      ok: true,
      record_id: recordId,
      well_id: wellId,
      sha256_hash: hash,
      rule_set_version: evaluation.rule_set_version,
      state: evaluation.state,
      rule_results: evaluation.rule_results,
      evaluation_trace: evaluation.evaluation_trace,
      final_outcome: evaluation.final_outcome,
      decision_hash: evaluation.decision_hash,
      xrpl_tx_hash,
      xrpl_explorer_url,
      wallet_address,
      xrpl_anchor_status,
      xrpl_anchor_error,
      tokenization_ready,
      mpt_status
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/mpt/issue", requireApiKey, async (req, res) => {
  try {
    const { record_id } = req.body;

    if (!record_id) {
      return res.status(400).json({ ok: false, error: "record_id required" });
    }

    const record = await get(
      `SELECT r.*, e.final_outcome, e.decision_hash, e.rule_set_version
       FROM records r
       LEFT JOIN rule_evaluations e ON e.record_id = r.id
       WHERE r.id = ?`,
      [record_id]
    );

    if (!record) {
      return res.status(404).json({ ok: false, error: "record not found" });
    }

    const tokenization_ready =
      record.final_outcome === "ELIGIBLE_FOR_REVIEW" &&
      !!record.xrpl_tx_hash;

    if (!tokenization_ready) {
      return res.status(400).json({
        ok: false,
        error: "record_not_tokenization_ready"
      });
    }

    const mptAsset = buildMptAsset(record);
    const issued = await issueMPT(mptAsset);

    await run(
      `UPDATE records
       SET status = ?, mpt_asset_id = ?, mpt_tx_hash = ?, mpt_issued_at_utc = ?
       WHERE id = ?`,
      [
        "MPT_ISSUED",
        issued.mptAssetId,
        issued.txHash,
        issued.issuedAt,
        record_id
      ]
    );

    await run(
      "INSERT INTO events (record_id, event_type, message, created_at_utc) VALUES (?, ?, ?, ?)",
      [
        record_id,
        "mpt_issued",
        JSON.stringify({
          mptAssetId: issued.mptAssetId,
          txHash: issued.txHash,
          issuedAt: issued.issuedAt,
          asset: issued.asset
        }),
        utcNow()
      ]
    );

    res.json({
      ok: true,
      record_id,
      tokenization_ready: true,
      mpt_status: "issued",
      mpt_asset_id: issued.mptAssetId,
      mpt_tx_hash: issued.txHash,
      mpt_issued_at_utc: issued.issuedAt
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/verify", requireApiKey, requireAuth, async (req, res) => {
  try {
    const { record_id, payload } = req.body;
    const record = await get("SELECT * FROM records WHERE id = ?", [record_id]);
    if (!record) {
      return res.status(404).json({ ok: false, error: "record not found" });
    }

    const evalRow = await get(
      "SELECT * FROM rule_evaluations WHERE record_id = ? ORDER BY id DESC LIMIT 1",
      [record_id]
    );

    const recomputedHash = sha256(payload);
    const valid = recomputedHash === record.sha256_hash;

    res.json({
      ok: true,
      record_id,
      valid,
      stored_hash: record.sha256_hash,
      recomputed_hash: recomputedHash,
      final_outcome: evalRow ? evalRow.final_outcome : null,
      decision_hash: evalRow ? evalRow.decision_hash : null,
      rule_set_version: evalRow ? evalRow.rule_set_version : null,
      xrpl_tx_hash: record.xrpl_tx_hash,
      xrpl_explorer_url: record.xrpl_explorer_url,
      mpt_asset_id: record.mpt_asset_id || null,
      mpt_tx_hash: record.mpt_tx_hash || null,
      mpt_issued_at_utc: record.mpt_issued_at_utc || null
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/records", requireApiKey, requireAuth, async (req, res) => {
  try {
    const rows = await all(
      "SELECT r.*, e.final_outcome, e.decision_hash, e.rule_set_version FROM records r LEFT JOIN rule_evaluations e ON e.record_id = r.id ORDER BY r.id DESC LIMIT 100"
    );
    res.json({ ok: true, records: rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/records/:id", requireApiKey, requireAuth, async (req, res) => {
  try {
    const record = await get("SELECT * FROM records WHERE id = ?", [req.params.id]);
    if (!record) {
      return res.status(404).json({ ok: false, error: "record not found" });
    }

    const events = await all(
      "SELECT * FROM events WHERE record_id = ? ORDER BY id ASC",
      [req.params.id]
    );

    const evaluation = await get(
      "SELECT * FROM rule_evaluations WHERE record_id = ? ORDER BY id DESC LIMIT 1",
      [req.params.id]
    );

    res.json({ ok: true, record, events, evaluation });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/admin/users", requireAuth, requireRole("approver"), async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const bcrypt = require("bcryptjs");
    const hash = await bcrypt.hash(password, 10);

    await run(
      "INSERT INTO users(email,password_hash,role,created_at_utc) VALUES (?,?,?,?)",
      [email, hash, role, new Date().toISOString()]
    );

    await logAudit({
      actor: req.user.email,
      action: "create_user",
      entity: "user",
      entity_id: email
    });

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/api/admin/users", requireAuth, requireRole("approver"), async (req, res) => {
  const users = await all("SELECT id,email,role,is_active FROM users");
  res.json({ ok: true, users });
});

app.get("/api/admin/audit", requireAuth, requireRole("approver"), async (req, res) => {
  const logs = await all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200");
  res.json({ ok: true, logs });
});

app.get("/", (req, res) => {
  res.json({ ok: true, service: "wellx-backend", message: "API is running" });
});

initDb().then(async () => {
  await ensureBootstrapAdmin();
  await ensureDefaultRuleSet();
  app.listen(PORT, () => console.log(`WellX MVP v1.6 running on http://localhost:${PORT}`));
});