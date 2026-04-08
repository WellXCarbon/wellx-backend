
const { run } = require("./db");
async function logAudit({ actor, action, entity, entity_id, details }) {
  await run(
    "INSERT INTO audit_logs(actor, action, entity, entity_id, details_json, created_at_utc) VALUES (?,?,?,?,?,?)",
    [actor, action, entity, entity_id, JSON.stringify(details||{}), new Date().toISOString()]
  );
}
module.exports = { logAudit };
