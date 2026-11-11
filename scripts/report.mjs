// node scripts/report.mjs -> data/results.json (the numbers quoted in the README and the email)
// Same code and data the page runs; default policy = 1 in 200 legitimate findings, 95% confidence, guard on.
import { readFileSync, writeFileSync } from 'node:fs';
import * as K from '../src/containment.js';

export function computeResults(world, { alphaInv = 200, conf = 95, coverage = 'business' } = {}) {
  const P = K.prepare(world);
  const a = 1 / alphaInv;
  const policy = K.calibratePolicy(P.cal, { exec: a, travel: a, other: a }, 1 - conf / 100);
  const run = (mode, guard, extra = {}) => K.replay(P.test, { policy, mode, guard, coverage, ...extra });
  const cal = run('calibrated', true), noGuard = run('calibrated', false), review = run('off', false), fixed = run('fixed', false, { fixedThr: 0.9 });
  const round = x => (x === null || !isFinite(x)) ? null : +x.toFixed(4);
  const m = r => Object.fromEntries(Object.entries(r.metrics).map(([k, v]) => [k, typeof v === 'number' ? round(v) : v]));
  return {
    settings: { alphaInv, alpha: a, confidence: conf / 100, coverage, calibrationWeeks: P.calWeeks, testWeeks: P.testWeeks, likelyBar: K.LIKELY },
    findings: world.findings.length, takeovers: world.findings.filter(f => f.y).length,
    model: { features: K.FEATURES, weights: P.model.w.map(round), bias: round(P.model.b) },
    policy: Object.fromEntries(K.GROUPS.map(g => { const c = policy[g]; return [g, { certified: c.certified, threshold: c.threshold, n: c.n, k: c.k, p: round(c.p), deltaGroup: round(c.deltaGroup), calTpr: round(c.calTpr), nAto: c.nAto }]; })),
    replay: { calibratedGuard: m(cal), calibratedNoGuard: m(noGuard), reviewOnly: m(review), fixed090: m(fixed), paused: cal.paused },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const world = JSON.parse(readFileSync(new URL('../data/tenant.json', import.meta.url)));
  const res = computeResults(world);
  writeFileSync(new URL('../data/results.json', import.meta.url), JSON.stringify(res, null, 2));
  const c = res.replay.calibratedGuard, r = res.replay.reviewOnly;
  console.log(`contained ${c.autoContained}/${c.atos}, median ${K.fmtDuration(c.medianContainMin)} vs ${K.fmtDuration(r.medianContainMin)}, steps ${c.preventedTotal}/${c.stepsTotal} vs ${r.preventedTotal}, wrong ${c.wrong}/${c.legit} (no guard ${res.replay.calibratedNoGuard.wrong})`);
  for (const [g, p] of Object.entries(res.policy)) console.log(g, p);
}
