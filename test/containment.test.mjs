import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as K from '../src/containment.js';
import { computeResults } from '../scripts/report.mjs';

const world = JSON.parse(readFileSync(new URL('../data/tenant.json', import.meta.url)));
const results = JSON.parse(readFileSync(new URL('../data/results.json', import.meta.url)));

test('binomial cdf matches direct sums and edge cases', () => {
  // Bin(10, 0.3): P(X <= 2) = 0.3827827864
  assert.ok(Math.abs(K.binomCdf(2, 10, 0.3) - 0.3827827864) < 1e-9);
  assert.equal(K.binomCdf(-1, 10, 0.3), 0);
  assert.equal(K.binomCdf(10, 10, 0.3), 1);
  // (1-p)^n for k = 0
  assert.ok(Math.abs(K.binomCdf(0, 1200, 0.005) - Math.pow(0.995, 1200)) < 1e-12);
});

test('lgamma agrees with log factorials', () => {
  let lf = 0;
  for (let n = 1; n <= 170; n++) { lf += Math.log(n); assert.ok(Math.abs(K.lgamma(n + 1) - lf) < 1e-8 * Math.max(1, lf), `n=${n}`); }
});

test('Clopper-Pearson upper bound inverts the binomial tail', () => {
  for (const [k, n] of [[0, 300], [3, 1000], [12, 1600]]) {
    const u = K.cpUpper(k, n, 0.05);
    assert.ok(Math.abs(K.binomCdf(k, n, u) - 0.05) < 1e-6);
    assert.ok(u > k / n);
  }
  // rule of three: k = 0 gives about 3/n at 95%
  assert.ok(Math.abs(K.cpUpper(0, 3000, 0.05) - 3 / 3000) < 2e-5);
});

test('minimum sample size for zero-event certification', () => {
  assert.equal(K.minSamples(0.005, 0.05 / 3), Math.ceil(Math.log(0.05 / 3) / Math.log(0.995)));
  const n = K.minSamples(0.01, 0.05);
  assert.ok(Math.pow(0.99, n) <= 0.05 && Math.pow(0.99, n - 1) > 0.05);
});

test('LTT refuses to certify with too little history', () => {
  const few = Array.from({ length: 100 }, (_, i) => i / 1000); // all far below any useful threshold
  const r = K.lttCertify(few, 0.005, 0.05);
  assert.equal(r.certified, false);
  assert.ok(r.minN > 100);
});

test('LTT threshold is monotone in alpha and never exceeds the limit on its own data', () => {
  const rnd = K.mulberry32(7);
  const s = Array.from({ length: 4000 }, () => Math.pow(rnd(), 6));
  let prev = Infinity;
  for (const a of [0.002, 0.005, 0.01, 0.02]) {
    const r = K.lttCertify(s, a, 0.05);
    assert.ok(r.certified);
    assert.ok(r.threshold <= prev + 1e-12, 'looser alpha must not raise the threshold');
    assert.ok(r.k / r.n <= a, 'empirical rate at the certified threshold is below alpha');
    prev = r.threshold;
  }
});

test('property: LTT controls the true wrong-revocation rate (randomised, 400 trials)', () => {
  // Benign scores ~ Beta(1, 9) via inverse CDF, so FPR(l) = (1 - l)^9 is known exactly.
  const rnd = K.mulberry32(20261108);
  const alpha = 0.01, delta = 0.1; let violations = 0; const trials = 400;
  for (let t = 0; t < trials; t++) {
    const s = Array.from({ length: 1500 }, () => 1 - Math.pow(rnd(), 1 / 9));
    const r = K.lttCertify(s, alpha, delta);
    if (r.certified && Math.pow(1 - r.threshold, 9) > alpha) violations++;
  }
  // P(violation) <= delta; allow binomial slack: mean 40 at the bound, sd ~6
  assert.ok(violations / trials <= delta + 0.03, `violation rate ${violations / trials}`);
});

test('property: guard false-pause rate stays under delta when the rate is at the limit', () => {
  const rnd = K.mulberry32(99);
  const alpha = 0.005, deltaGuard = 0.05; let pauses = 0; const trials = 300;
  for (let t = 0; t < trials; t++) {
    let st = { comps: null, e: 1 };
    for (let i = 0; i < 3000; i++) { st = K.guardStep(st, rnd() < alpha, alpha); if (st.e >= 1 / deltaGuard) { pauses++; break; } }
  }
  assert.ok(pauses / trials <= deltaGuard + 0.02, `false pause rate ${pauses / trials}`);
});

test('guard trips quickly when the rate is 8x the limit', () => {
  const rnd = K.mulberry32(3); const alpha = 0.005; let st = { comps: null, e: 1 }, n = 0;
  while (st.e < 20 && n < 5000) { st = K.guardStep(st, rnd() < 8 * alpha, alpha); n++; }
  assert.ok(st.e >= 20 && n < 2000, `took ${n}`);
});

test('featurize reproduces the impossible-travel signal from raw events', () => {
  const w = { cities: [{ name: 'Chicago', country: 'US', lat: 41.88, lon: -87.63, tz: -5 }, { name: 'Amsterdam', country: 'NL', lat: 52.37, lon: 4.9, tz: 2 }] };
  const acct = { home: 0, traveler: 0, vpn: 0, rules: 0 };
  const f = { t: 0, ev: [['S', -19, 0, 24, 'c', 0, 0, 1], ['S', 0, 1, 77, 'h', 1, 6, 2], ['R', 5, '.', 1, 'RSS Subscriptions', 1]] };
  const { x, km, minutes } = K.featurize(f, acct, w);
  const idx = n => K.FEATURES.indexOf(n);
  assert.ok(Math.abs(km - 6600) < 100, `km ${km}`);
  assert.equal(minutes, 19);
  for (const n of ['impossible_travel', 'new_country', 'new_country_nontraveler', 'first_seen_device', 'hosting_unusual', 'rule_hidden', 'rule_payment_terms', 'first_rule_ever']) assert.equal(x[idx(n)], 1, n);
  assert.equal(x[idx('session_two_ips')], 0);
  // prefix: before the rule exists
  assert.equal(K.featurize(f, acct, w, 0).x[idx('rule_created')], 0);
});

test('running score: first crossing equals max-score test (the certified trigger)', () => {
  const P = K.prepare(world);
  for (const r of P.test.slice(0, 600)) {
    for (const thr of [0.1, 0.25, 0.5]) assert.equal(K.firstCross(r.run, thr) !== null, r.max >= thr);
  }
});

test('replay respects the certificate on calibration-like weeks (no wrong revocations above alpha before the shift)', () => {
  const P = K.prepare(world);
  const a = 1 / 200, pol = K.calibratePolicy(P.cal, { exec: a, travel: a, other: a }, 0.05);
  const R = K.replay(P.test.filter(r => r.f.w !== 23), { policy: pol, guard: false });
  for (const g of K.GROUPS) { const b = R.metrics.byGroup[g]; assert.ok(b.wrong / b.legit <= a, `${g}: ${b.wrong}/${b.legit}`); }
});

test('headline numbers in data/results.json are reproduced from data + code', () => {
  const fresh = computeResults(world);
  assert.deepEqual(fresh.replay.calibratedGuard, results.replay.calibratedGuard);
  assert.deepEqual(fresh.policy, results.policy);
  const c = results.replay.calibratedGuard;
  assert.ok(c.autoContained > results.replay.fixed090.autoContained, 'calibrated contains more than a fixed 0.90 bucket');
  assert.ok(c.medianContainMin < results.replay.reviewOnly.medianContainMin);
  assert.ok(c.wrong < results.replay.calibratedNoGuard.wrong, 'guard reduces wrong revocations under the Lisbon shift');
});

test('CSV export escapes commas and quotes', () => {
  const s = K.toCSV([{ a: 'x,y', b: 'say "hi"', c: null }], ['a', 'b', 'c']);
  assert.equal(s, 'a,b,c\n"x,y","say ""hi""",');
});
