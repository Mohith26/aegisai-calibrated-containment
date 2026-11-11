// Calibrated auto-containment for account-takeover findings.
// Pure functions, no DOM. Runs in the browser (ES module) and in Node (tests, report script).
//
// Pieces:
//   1. featurize()        signals an analyst would read, computed from the finding's raw events
//   2. trainLogistic()    finding score (stand-in for the product's own confidence score)
//   3. lttCertify()       Learn-then-Test, fixed-sequence: pick the lowest score threshold whose
//                         wrong-revocation rate among legitimate findings is certified <= alpha
//                         with probability >= 1 - delta (exact binomial, finite sample)
//   4. calibratePolicy()  one certificate per account group, Bonferroni across groups
//   5. replay()           counterfactual replay of held-out weeks: who gets revoked, when,
//                         which attacker steps are prevented, analyst path for the rest
//   6. guard              anytime-valid e-process that pauses a group if live labels show the
//                         certified rate is being exceeded (distribution shift)

// ---------------------------------------------------------------- rng / math
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const LANCZOS = [676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059,
  12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
export function lgamma(x) {
  if (x < 0.5) return Math.log(Math.PI / Math.abs(Math.sin(Math.PI * x))) - lgamma(1 - x);
  x -= 1;
  let a = 0.99999999999980993;
  const t = x + 7.5;
  for (let i = 0; i < 8; i++) a += LANCZOS[i] / (x + i + 1);
  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}
function logChoose(n, k) { return lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1); }

// P(X <= k) for X ~ Binomial(n, p). Summed in log space, stable for n up to ~1e6.
export function binomCdf(k, n, p) {
  if (k < 0) return 0;
  if (k >= n) return 1;
  if (p <= 0) return 1;
  if (p >= 1) return 0;
  const lp = Math.log(p), lq = Math.log1p(-p);
  let m = -Infinity; const terms = [];
  for (let i = 0; i <= k; i++) { const v = logChoose(n, i) + i * lp + (n - i) * lq; terms.push(v); if (v > m) m = v; }
  let s = 0; for (const v of terms) s += Math.exp(v - m);
  return Math.min(1, Math.exp(m + Math.log(s)));
}

// One-sided Clopper-Pearson upper bound: smallest p with P(Bin(n,p) <= k) <= delta.
export function cpUpper(k, n, delta) {
  if (n === 0) return 1;
  if (k >= n) return 1;
  let lo = k / n, hi = 1;
  for (let it = 0; it < 80; it++) { const mid = (lo + hi) / 2; if (binomCdf(k, n, mid) > delta) lo = mid; else hi = mid; }
  return hi;
}

export function haversineKm(a, b) {
  const R = 6371, rad = Math.PI / 180;
  const dLat = (b.lat - a.lat) * rad, dLon = (b.lon - a.lon) * rad;
  const s = Math.sin(dLat / 2) ** 2 + Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(s)));
}

export function quantile(sorted, q) {
  if (!sorted.length) return NaN;
  const pos = (sorted.length - 1) * q, lo = Math.floor(pos), hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

// ---------------------------------------------------------------- features
// Event encoding (compact, as stored in data/tenant.json):
//   ["S", dtMin, city, ipOctet, asn(h|m|r|c), newDevice(0/1), osIdx, session]   sign-in
//   ["P", dtMin, denials]                                               MFA push denials before approval
//   ["M", dtMin, method]                                                MFA method registered
//   ["R", dtMin, name, keywords(0/1), action, markRead(0/1)]            inbox rule created
//   ["X", dtMin, count]                                                 internal sends burst
// The first event is always the account's last normal sign-in (baseline).
export const FEATURES = [
  'impossible_travel', 'new_country', 'new_country_nontraveler', 'first_seen_device', 'hosting_unusual',
  'hosting_habitual', 'session_two_ips', 'mfa_push_burst', 'mfa_method_added', 'rule_created', 'rule_hidden',
  'rule_payment_terms', 'first_rule_ever', 'internal_send_burst', 'off_hours', 'mobile_network',
];
export const HIDDEN_ACTIONS = new Set(['RSS Subscriptions', 'Archive', 'Conversation History', 'Deleted Items']);

export function cityOf(world, idx) { return world.cities[idx]; }

// Returns {x: Float64Array, speedKmh, km, minutes} using only events with dt <= upto.
export function featurize(f, acct, world, upto = Infinity) {
  const x = new Float64Array(FEATURES.length);
  const ev = f.ev.filter(e => e[1] <= upto);
  const base = ev[0];
  const home = cityOf(world, acct.home);
  let speedKmh = 0, km = 0, minutes = 0;
  const sessions = new Map();
  for (let i = 1; i < ev.length; i++) {
    const e = ev[i];
    if (e[0] === 'S') {
      const prevCity = cityOf(world, base[2]), cur = cityOf(world, e[2]);
      const d = haversineKm(prevCity, cur), dt = Math.max(1, e[1] - base[1]);
      const v = d / (dt / 60);
      if (v > speedKmh) { speedKmh = v; km = d; minutes = dt; }
      if (v > 900 && d > 500) x[0] = 1;
      if (cur.country !== home.country) { x[1] = 1; if (!acct.traveler) x[2] = 1; }
      if (e[5]) x[3] = 1;
      if (e[4] === 'h') { if (acct.vpn) x[5] = 1; else x[4] = 1; }
      if (e[4] === 'm') x[15] = 1;
      const local = localHour(f.t + e[1], cur.tz);
      if (local.h < 7 || local.h >= 20 || local.dow === 0 || local.dow === 6) x[14] = 1;
    }
    if (e[0] === 'P' && e[2] >= 3) x[7] = 1;
    if (e[0] === 'M') x[8] = 1;
    if (e[0] === 'R') {
      x[9] = 1;
      if (HIDDEN_ACTIONS.has(e[4]) && e[5]) x[10] = 1;
      if (e[3]) x[11] = 1;
      if (!acct.rules) x[12] = 1;
    }
    if (e[0] === 'X' && e[2] >= 25) x[13] = 1;
  }
  // a session token seen from two different IPs within the window
  for (const e of ev) if (e[0] === 'S' && e[7]) { const s = sessions.get(e[7]) || new Set(); s.add(e[3]); sessions.set(e[7], s); }
  for (const s of sessions.values()) if (s.size > 1) x[6] = 1;
  return { x, speedKmh, km, minutes };
}

// minutes since world epoch (UTC) -> local hour/day-of-week for a fixed UTC offset
export let EPOCH_MS = Date.UTC(2026, 4, 11); // Mon 11 May 2026 00:00 UTC
export function localHour(tMin, tz) {
  const d = new Date(EPOCH_MS + (tMin + tz * 60) * 60000);
  return { h: d.getUTCHours(), dow: d.getUTCDay() };
}

// ---------------------------------------------------------------- score model
export function sigmoid(z) { return 1 / (1 + Math.exp(-z)); }

// L2-regularised logistic regression, full-batch gradient descent with a fixed schedule
// (deterministic: same data in, same weights out).
export function trainLogistic(X, y, { l2 = 0.02, iters = 1500, lr = 0.5, posWeight = 1 } = {}) {
  const d = X[0].length, n = X.length;
  const w = new Float64Array(d); let b = 0;
  let wsum = 0; for (let i = 0; i < n; i++) wsum += y[i] ? posWeight : 1;
  for (let it = 0; it < iters; it++) {
    const g = new Float64Array(d); let gb = 0;
    for (let i = 0; i < n; i++) {
      let z = b; const xi = X[i];
      for (let j = 0; j < d; j++) z += w[j] * xi[j];
      const wt = y[i] ? posWeight : 1;
      const r = (sigmoid(z) - y[i]) * wt;
      for (let j = 0; j < d; j++) g[j] += r * xi[j];
      gb += r;
    }
    for (let j = 0; j < d; j++) w[j] -= lr * (g[j] / wsum + l2 * w[j]);
    b -= lr * gb / wsum;
  }
  return { w: Array.from(w), b };
}
export function scoreX(model, x) { let z = model.b; for (let j = 0; j < x.length; j++) z += model.w[j] * x[j]; return sigmoid(z); }

// Running score at every event time. Containment triggers the first time the running score
// crosses the threshold, i.e. exactly when max(running) >= threshold, so calibrating on the
// max score is calibrating the trigger itself.
export function runningScores(f, acct, world, model) {
  const out = [];
  for (let i = 1; i < f.ev.length; i++) {
    const t = f.ev[i][1];
    if (i + 1 < f.ev.length && f.ev[i + 1][1] === t) continue;
    out.push({ t, s: scoreX(model, featurize(f, acct, world, t).x) });
  }
  return out;
}
export function firstCross(run, thr) { for (const r of run) if (r.s >= thr) return r.t; return null; }
export function maxScore(run) { let m = 0; for (const r of run) if (r.s > m) m = r.s; return m; }

// ---------------------------------------------------------------- Learn-then-Test
// Data-independent grid, tested from the strictest threshold down (fixed-sequence testing:
// FWER <= delta for any pre-specified order; the risk is monotone in the threshold, so this
// order loses nothing). H0(lambda): FPR(lambda) > alpha. p = P(Bin(n, alpha) <= k(lambda)).
export const GRID = Array.from({ length: 1001 }, (_, i) => 1 - i / 1000);

export function lttCertify(benignMax, alpha, delta, grid = GRID) {
  const s = Float64Array.from(benignMax).sort().reverse();
  const n = s.length;
  let ptr = 0, last = null; const path = [];
  for (const lam of grid) {
    while (ptr < n && s[ptr] >= lam - 1e-12) ptr++;
    const k = ptr, p = binomCdf(k, n, alpha);
    path.push({ lam, k, p });
    if (p <= delta) last = { lam, k, p }; else break;
  }
  if (!last) return { certified: false, n, threshold: null, k: null, p: path[0] ? path[0].p : 1, minN: minSamples(alpha, delta), path };
  return { certified: true, n, threshold: last.lam, k: last.k, p: last.p, empirical: last.k / n,
    ucb: cpUpper(last.k, n, delta), path };
}
// Smallest n for which zero wrong revocations certifies alpha: (1-alpha)^n <= delta.
export function minSamples(alpha, delta) { return Math.ceil(Math.log(delta) / Math.log1p(-alpha)); }

// ---------------------------------------------------------------- data prep
export const GROUPS = ['exec', 'travel', 'other'];
export const GROUP_LABEL = { exec: 'Executives & finance', travel: 'Frequent travelers', other: 'Everyone else' };

export function prepare(world, { trainWeeks = [1, 10], calWeeks = [11, 18], testWeeks = [19, 26] } = {}) {
  const acct = world.accounts;
  const train = world.findings.filter(f => f.w >= trainWeeks[0] && f.w <= trainWeeks[1]);
  const X = [], y = [];
  // train on prefix snapshots as well as the full window so the score is meaningful mid-attack
  for (const f of train) {
    const a = acct[f.a];
    const times = [...new Set(f.ev.slice(1).map(e => e[1]))];
    for (const t of times) { X.push(featurize(f, a, world, t).x); y.push(f.y); }
  }
  const model = trainLogistic(X, y, { l2: 1e-3, iters: 2500, lr: 1.0 });
  const rows = world.findings.map(f => {
    const a = acct[f.a];
    const run = runningScores(f, a, world, model);
    return { f, a, g: a.g, run, max: maxScore(run) };
  });
  const inW = (r, w) => r.f.w >= w[0] && r.f.w <= w[1];
  return { model, rows, cal: rows.filter(r => inW(r, calWeeks)), test: rows.filter(r => inW(r, testWeeks)), trainWeeks, calWeeks, testWeeks };
}

export function calibratePolicy(cal, alphaByGroup, delta) {
  const G = GROUPS.length, dg = delta / G, out = {};
  for (const g of GROUPS) {
    const benign = cal.filter(r => r.g === g && !r.f.y).map(r => r.max);
    const atos = cal.filter(r => r.g === g && r.f.y);
    const cert = lttCertify(benign, alphaByGroup[g], dg);
    const tpr = cert.certified ? atos.filter(r => r.max >= cert.threshold).length / Math.max(1, atos.length) : 0;
    out[g] = { ...cert, alpha: alphaByGroup[g], deltaGroup: dg, nAto: atos.length, calTpr: tpr };
  }
  return out;
}

// ---------------------------------------------------------------- analyst baseline
// Queue entry when the running score first reaches the "Likely takeover" bar (0.5), plus the
// audit-log delay. Analyst delay is lognormal (stored normal deviate z per finding):
// business hours (Mon-Fri 08-18 SOC time) median 38 min; otherwise wait for 08:00 then median 25 min.
export const LIKELY = 0.1;
export const ANALYST = { tz: -5, bizMedian: 38, offMedian: 25, sigma: 0.9, coverage: 'business' };
export const REVOKE_API_SEC = 5;
export function analystDelay(tMin, z, A = ANALYST) {
  const { h, dow } = localHour(tMin, A.tz);
  const biz = A.coverage === '24x7' || (dow >= 1 && dow <= 5 && h >= 8 && h < 18);
  if (biz) return A.bizMedian * Math.exp(A.sigma * z);
  // minutes until next business-day 08:00
  let wait = 0, t = tMin;
  for (let i = 0; i < 4 * 24 * 60; i += 15) {
    const L = localHour(t, A.tz);
    if (L.dow >= 1 && L.dow <= 5 && L.h >= 8 && L.h < 18) break;
    t += 15; wait += 15;
  }
  return wait + A.offMedian * Math.exp(A.sigma * z);
}

// ---------------------------------------------------------------- guard (anytime-valid)
// Mixture likelihood-ratio e-process for H0: FPR <= alpha, over legitimate findings in time order.
// X_t = 1 if the legitimate finding was revoked. Under H0 every component is a nonnegative
// supermartingale, so by Ville's inequality P(ever >= 1/deltaGuard) <= deltaGuard.
export function guardFactors(alpha) {
  return [2, 4, 8].map(m => Math.min(0.5, m * alpha)).map(p1 => ({ p1, up: p1 / alpha, down: (1 - p1) / (1 - alpha) }));
}
export function guardStep(state, revoked, alpha) {
  const fs = guardFactors(alpha);
  const comps = state.comps || fs.map(() => 1);
  const next = comps.map((c, i) => c * (revoked ? fs[i].up : fs[i].down));
  const e = next.reduce((a, b) => a + b, 0) / next.length;
  return { comps: next, e };
}

// ---------------------------------------------------------------- replay
// opts: { policy (from calibratePolicy), mode: 'calibrated'|'fixed'|'off', fixedThr, guard: bool, deltaGuard,
//         feedback: {findingId: 'legit'|'ato'} (analyst corrections recorded in the UI) }
export function replay(test, opts) {
  const { policy, mode = 'calibrated', fixedThr = 0.9, guard = true, deltaGuard = 0.05, feedback = {}, coverage = 'business' } = opts;
  const A = { ...ANALYST, coverage };
  const rows = [...test].sort((a, b) => a.f.t - b.f.t);
  const gstate = {}; const paused = {}; const guardTrace = { exec: [], travel: [], other: [] };
  for (const g of GROUPS) { gstate[g] = { comps: null, e: 1 }; paused[g] = null; }
  const decisions = [];
  for (const r of rows) {
    const f = r.f, g = r.g;
    const label = feedback[f.id] ? (feedback[f.id] === 'ato' ? 1 : 0) : f.y;
    let thr = null;
    if (mode === 'fixed') thr = fixedThr;
    else if (mode === 'calibrated' && policy[g] && policy[g].certified) thr = policy[g].threshold;
    const isPaused = paused[g] !== null && paused[g] <= f.t;
    const cross = thr !== null && !isPaused ? firstCross(r.run, thr) : null;
    const auto = cross !== null;
    const tAuto = auto ? cross + f.d + REVOKE_API_SEC / 60 : null;
    const qCross = firstCross(r.run, LIKELY);
    const tQueue = qCross !== null ? qCross + f.d : null;
    const tAnalyst = tQueue !== null ? tQueue + analystDelay(f.t + tQueue, f.z, A) : null;
    const tContain = auto ? tAuto : (label ? tAnalyst : null);
    // attacker steps after the first malicious sign-in that containment would have prevented
    const steps = f.ev.filter(e => e[1] > 0 && (e[0] === 'R' || e[0] === 'X' || e[0] === 'M'));
    const prevented = auto ? steps.filter(e => e[1] > tAuto).length : 0;
    const preventedAnalyst = label && tAnalyst !== null ? steps.filter(e => e[1] > tAnalyst).length : 0;
    const d = { id: f.id, t: f.t, w: f.w, g, y: label, max: r.max, auto, tAuto, tQueue, tAnalyst, tContain,
      wrong: auto && !label, steps: steps.length, prevented, preventedAnalyst, review: !auto && qCross !== null };
    decisions.push(d);
    if (!label && mode !== 'off' && thr !== null) {
      // legitimate finding resolved: feed the guard (only while automation is active for the group)
      if (!isPaused) {
        gstate[g] = guardStep(gstate[g], auto, policy && policy[g] ? policy[g].alpha : 0.005);
        guardTrace[g].push({ t: f.t, e: gstate[g].e, revoked: auto, id: f.id });
        if (guard && gstate[g].e >= 1 / deltaGuard && paused[g] === null) paused[g] = f.t + 1;
      }
    }
  }
  return { decisions, paused, guardTrace, metrics: summarize(decisions) };
}

export function summarize(decisions) {
  const atos = decisions.filter(d => d.y), legit = decisions.filter(d => !d.y);
  const auto = atos.filter(d => d.auto);
  const autoTimes = auto.map(d => d.tAuto).sort((a, b) => a - b);
  const anaTimes = atos.filter(d => d.tAnalyst !== null).map(d => d.tAnalyst).sort((a, b) => a - b);
  const contain = atos.filter(d => d.tContain !== null).map(d => d.tContain).sort((a, b) => a - b);
  const stepsTotal = atos.reduce((s, d) => s + d.steps, 0);
  const prevented = atos.reduce((s, d) => s + d.prevented, 0);
  const preventedAnalyst = atos.reduce((s, d) => s + d.preventedAnalyst, 0);
  // steps stopped by whoever contained the account first (automation, else the analyst)
  const preventedTotal = atos.reduce((s, d) => s + (d.auto ? d.prevented : d.preventedAnalyst), 0);
  const byGroup = {};
  for (const g of GROUPS) {
    const a = atos.filter(d => d.g === g), l = legit.filter(d => d.g === g);
    byGroup[g] = { atos: a.length, auto: a.filter(d => d.auto).length, legit: l.length, wrong: l.filter(d => d.wrong).length };
  }
  return {
    atos: atos.length, autoContained: auto.length, legit: legit.length, wrong: legit.filter(d => d.wrong).length,
    reviewQueue: decisions.filter(d => d.review).length,
    reviewQueueToday: decisions.filter(d => d.tQueue !== null).length,
    medianAutoMin: quantile(autoTimes, 0.5), medianAnalystMin: quantile(anaTimes, 0.5), medianContainMin: quantile(contain, 0.5),
    stepsTotal, prevented, preventedAnalyst, preventedTotal, byGroup,
  };
}

// ---------------------------------------------------------------- export
export function toCSV(rows, cols) {
  const esc = v => { const s = v === null || v === undefined ? '' : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  return [cols.join(','), ...rows.map(r => cols.map(c => esc(r[c])).join(','))].join('\n');
}

export function fmtDuration(min) {
  if (min === null || min === undefined || !isFinite(min)) return '—';
  if (min < 1) return Math.round(min * 60) + ' s';
  if (min < 60) return Math.round(min) + ' min';
  const h = Math.floor(min / 60), m = Math.round(min % 60);
  return h + ' h ' + String(m).padStart(2, '0') + ' min';
}
