// Plain helpers — no express/koa routes, no req/res handlers.
function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}
module.exports = { clamp };
