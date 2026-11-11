// Seeded synthetic tenant: 26 weeks of account-takeover findings for a 3,000-mailbox org.
// node scripts/generate.mjs  ->  data/tenant.json
// Every random draw comes from mulberry32(SEED). Rates below are assumptions unless a source is named.
import { writeFileSync } from 'node:fs';
import { mulberry32 } from '../src/containment.js';

const SEED = 20261108;
const rnd = mulberry32(SEED);
const pick = a => a[Math.floor(rnd() * a.length)];
const bern = p => rnd() < p ? 1 : 0;
const uni = (a, b) => a + (b - a) * rnd();
const randn = () => { let u = 0, v = 0; while (u === 0) u = rnd(); while (v === 0) v = rnd(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); };
const poisson = lam => { // Knuth for small, normal approx for large
  if (lam > 60) return Math.max(0, Math.round(lam + Math.sqrt(lam) * randn()));
  let L = Math.exp(-lam), k = 0, p = 1; do { k++; p *= rnd(); } while (p > L); return k - 1;
};
function weighted(pairs) { const s = pairs.reduce((a, p) => a + p[1], 0); let u = rnd() * s; for (const [v, w] of pairs) { if ((u -= w) <= 0) return v; } return pairs[pairs.length - 1][0]; }

// tz = UTC offset in hours (fixed, autumn values)
const cities = [
  ['Chicago', 'US', 41.88, -87.63, -5], ['New York', 'US', 40.71, -74.01, -4], ['Austin', 'US', 30.27, -97.74, -5],
  ['London', 'GB', 51.51, -0.13, 1], ['San Francisco', 'US', 37.77, -122.42, -7], ['Denver', 'US', 39.74, -104.99, -6],
  ['Atlanta', 'US', 33.75, -84.39, -4], ['Boston', 'US', 42.36, -71.06, -4], ['Seattle', 'US', 47.61, -122.33, -7],
  ['Ashburn', 'US', 39.04, -77.49, -4], ['Dallas', 'US', 32.78, -96.80, -5], ['Toronto', 'CA', 43.65, -79.38, -4],
  ['Mexico City', 'MX', 19.43, -99.13, -6], ['Amsterdam', 'NL', 52.37, 4.90, 2], ['Frankfurt', 'DE', 50.11, 8.68, 2],
  ['Lisbon', 'PT', 38.72, -9.14, 1], ['Paris', 'FR', 48.86, 2.35, 2], ['Singapore', 'SG', 1.35, 103.82, 8],
  ['São Paulo', 'BR', -23.55, -46.63, -3], ['Lagos', 'NG', 6.52, 3.38, 1], ['Bucharest', 'RO', 44.43, 26.10, 3],
  ['Ho Chi Minh City', 'VN', 10.82, 106.63, 7], ['Dubai', 'AE', 25.20, 55.27, 4], ['Tokyo', 'JP', 35.68, 139.69, 9],
  ['Madrid', 'ES', 40.42, -3.70, 2], ['Mumbai', 'IN', 19.08, 72.88, 5.5],
].map(([name, country, lat, lon, tz]) => ({ name, country, lat, lon, tz }));
const C = Object.fromEntries(cities.map((c, i) => [c.name, i]));
const OFFICES = [[C.Chicago, 0.5], [C['New York'], 0.25], [C.Austin, 0.15], [C.London, 0.10]];
const US_TRAVEL = ['New York', 'San Francisco', 'Denver', 'Atlanta', 'Boston', 'Seattle', 'Dallas', 'Austin', 'Chicago'].map(n => C[n]);
const INTL_TRAVEL = ['London', 'Toronto', 'Mexico City', 'Paris', 'Frankfurt', 'Amsterdam', 'Singapore', 'Tokyo', 'Madrid', 'Dubai', 'São Paulo'].map(n => C[n]);
const HOSTING = ['Amsterdam', 'Frankfurt', 'Ashburn', 'Dallas', 'Singapore', 'Paris'].map(n => C[n]);
const ATTACKER = ['Lagos', 'Bucharest', 'Ho Chi Minh City', 'Amsterdam', 'Frankfurt', 'Ashburn', 'Dallas', 'São Paulo', 'Mumbai', 'Singapore'].map(n => C[n]);

const FIRST = ['Drew', 'Avery', 'Jordan', 'Priya', 'Marcus', 'Elena', 'Sam', 'Noah', 'Maya', 'Lucas', 'Grace', 'Omar', 'Hannah', 'Ethan', 'Sofia', 'Diego', 'Chloe', 'Ryan', 'Aisha', 'Ben', 'Nina', 'Kevin', 'Laura', 'Tariq', 'Mei', 'Jonah', 'Rosa', 'Victor', 'Ivy', 'Caleb', 'Zara', 'Felix', 'Hana', 'Owen', 'Leah', 'Arjun', 'Tess', 'Paul', 'Yuki', 'Nadia', 'Isaac', 'Ruth', 'Theo', 'Amara', 'Cole', 'Dana', 'Gabe', 'Iris', 'Jude', 'Kira', 'Liam', 'Mila', 'Nate', 'Olive', 'Pete', 'Quinn', 'Rhea', 'Seth', 'Uma', 'Wes'];
const LAST = ['Reyes', 'Chen', 'Patel', 'Okafor', 'Novak', 'Kim', 'Garcia', 'Brooks', 'Silva', 'Nguyen', 'Walsh', 'Haddad', 'Larsen', 'Ito', 'Mensah', 'Russo', 'Fischer', 'Shah', 'Murphy', 'Costa', 'Ward', 'Park', 'Becker', 'Diaz', 'Hughes', 'Rossi', 'Moreau', 'Singh', 'Adler', 'Bauer', 'Cruz', 'Dunn', 'Ellis', 'Flores', 'Grant', 'Holt', 'Iyer', 'Jensen', 'Klein', 'Lopez', 'Meyer', 'Nash', 'Ortiz', 'Price', 'Quinn', 'Ross', 'Stone', 'Torres', 'Vance', 'Wolfe'];
// [dept, share, group, travelerShare, vpnShare, ruleShare]
const DEPTS = [
  ['Finance', 0.09, 'exec', 0.05, 0.05, 0.75], ['Executive', 0.02, 'exec', 0.5, 0.05, 0.6], ['Legal', 0.03, 'exec', 0.1, 0.05, 0.7],
  ['Sales', 0.18, 'travel', 1, 0.05, 0.5], ['Field Services', 0.07, 'travel', 1, 0.05, 0.3],
  ['Engineering', 0.22, 'other', 0, 0.25, 0.6], ['Operations', 0.14, 'other', 0, 0.05, 0.4], ['Support', 0.12, 'other', 0, 0.05, 0.45],
  ['Marketing', 0.07, 'other', 0, 0.05, 0.6], ['People', 0.06, 'other', 0, 0.05, 0.5],
];

const N_ACCT = 3000;
const accounts = []; const used = new Set();
for (let i = 0; i < N_ACCT; i++) {
  const first = pick(FIRST), last = pick(LAST);
  const stem = `${first[0].toLowerCase()}.${last.toLowerCase()}`;
  let email = stem, k = 1;
  while (used.has(email)) email = stem + (++k);
  used.add(email);
  const [dept, , g, trav, vpn, rules] = weighted(DEPTS.map(d => [d, d[1]]));
  const home = weighted(OFFICES);
  const traveler = g === 'travel' ? 1 : bern(trav);
  accounts.push({ n: `${first} ${last}`, e: `${email}@northwind.example`, dept, g, home, traveler, vpn: bern(vpn), rules: bern(rules) });
}
const byGroup = { exec: [], travel: [], other: [] };
accounts.forEach((a, i) => byGroup[a.g].push(i));

const OS = [['Windows', 'Edge'], ['Windows', 'Chrome'], ['macOS', 'Safari'], ['macOS', 'Chrome'], ['iOS', 'Outlook'], ['Android', 'Outlook'], ['Linux', 'Chrome'], ['macOS', 'Firefox'], ['Android', 'Chrome']];
// Compact sign-in encoding: ['S', dt, city, ipOctet, asn, newDevice, osIdx, session]
// asn: h = hosting provider, m = mobile carrier, r = residential/hotel, c = corporate
let ipCounter = 0;
const ip = () => { ipCounter++; return 1 + (ipCounter * 37) % 253; };
let sessCounter = 0; const sess = () => ++sessCounter;
const ASN = { hosting: 'h', mobile: 'm', residential: 'r', corporate: 'c' };

function baseEvent(a) {
  return ['S', -Math.round(uni(20, 600)), a.home, ip(), bern(0.3) ? 'r' : 'c', 0, a.home % 2 === 0 ? 0 : 2, sess()];
}
function signIn(dt, city, asn, newDev, session) { const os = newDev ? pick([6, 1, 7, 8]) : pick([0, 1, 2, 3, 4, 5]); return ['S', dt, city, ip(), ASN[asn], newDev, os, session || sess()]; }

// ------------------------------------------------------------ benign finding types
function benign(type, a, ctx = {}) {
  const ev = [baseEvent(a)];
  const base = ev[0];
  if (type === 'travel') {
    const intl = bern(a.g === 'travel' ? 0.45 : 0.3);
    const city = ctx.city ?? (intl ? pick(INTL_TRAVEL) : pick(US_TRAVEL.filter(c => c !== a.home)));
    const glitch = bern(ctx.glitch ?? 0.12); // still on home VPN / roaming: travel time looks impossible
    if (!glitch) base[1] = -Math.round(uni(300, 1800));
    const asn = weighted([['hotel', 0.45], ['mobile', 0.4], ['hosting', ctx.hosting ?? 0.08]]);
    const s = sess();
    ev.push(signIn(0, city, asn === 'hotel' ? 'residential' : asn, bern(ctx.newDev ?? 0.1), s));
    if (bern(ctx.twoIps ?? 0.14)) ev.push(signIn(Math.round(uni(2, 40)), city, ctx.secondAsn ?? 'mobile', 0, s));
    if (bern(0.02)) ev.push(['R', Math.round(uni(5, 60)), 'Out of office filing', 0, 'Travel', 0]);
  } else if (type === 'vpn') {
    const city = pick(HOSTING); const s = sess();
    ev.push(signIn(0, city, 'hosting', bern(0.05), s));
    if (bern(0.25)) ev.push(signIn(Math.round(uni(1, 30)), pick(HOSTING), 'hosting', 0, s));
  } else if (type === 'new_device') {
    ev.push(signIn(0, a.home, 'residential', 1));
    if (bern(0.35)) ev.push(['M', Math.round(uni(1, 20)), 'Authenticator app']);
  } else if (type === 'phone') {
    ev.push(signIn(0, a.home, 'mobile', bern(0.8)));
    ev.push(['M', Math.round(uni(0, 10)), pick(['Authenticator app', 'Phone (SMS)'])]);
    if (bern(0.1)) ev.splice(1, 0, ['P', -1, Math.round(uni(3, 5))]);
  } else if (type === 'rule') {
    const fin = a.dept === 'Finance';
    const kw = bern(fin ? 0.3 : 0.05);
    const hidden = bern(0.22);
    ev.push(['R', 0, kw ? pick(['Invoices to AP folder', 'Vendor statements', 'Payment confirmations']) : pick(['Newsletters', 'Jira notifications', 'GitHub', 'Calendar replies', 'Vendor promos']),
      kw, hidden ? pick(['Archive', 'RSS Subscriptions', 'Conversation History']) : pick(['Reference', 'Projects', 'Receipts']), hidden ? 1 : bern(0.2)]);
  } else if (type === 'bulk') {
    ev.push(['X', 0, Math.round(uni(30, 400))]);
  } else if (type === 'push') {
    ev.push(['P', -1, Math.round(uni(3, 6))]);
    ev.push(signIn(0, a.home, 'residential', 0));
  }
  return ev;
}
const BENIGN_MIX = {
  exec: [['travel', 0.22], ['vpn', 0.08], ['new_device', 0.18], ['phone', 0.14], ['rule', 0.26], ['bulk', 0.04], ['push', 0.08]],
  travel: [['travel', 0.62], ['vpn', 0.05], ['new_device', 0.09], ['phone', 0.1], ['rule', 0.08], ['bulk', 0.02], ['push', 0.04]],
  other: [['travel', 0.12], ['vpn', 0.22], ['new_device', 0.2], ['phone', 0.14], ['rule', 0.17], ['bulk', 0.08], ['push', 0.07]],
};
const GROUP_RATE = { exec: 0.32, travel: 0.26, other: 0.085 }; // legitimate findings per account per week

// ------------------------------------------------------------ takeovers
// Technique mix: token theft 31% of MFA-bypass attacks (Verizon DBIR 2025, as cited on aegisai.com);
// the other shares are assumptions.
function takeover(a) {
  const kind = weighted([['token_theft', 0.31], ['mfa_fatigue', 0.24], ['helpdesk_reset', 0.15], ['no_mfa', 0.30]]);
  const ev = [baseEvent(a)];
  ev[0][1] = -Math.round(uni(2, 90));
  const city = pick(ATTACKER);
  if (kind === 'token_theft') {
    // victim authenticates through the proxy; attacker replays the session cookie from hosting infra
    const s = ev[0][7];
    ev.push(signIn(0, bern(0.82) ? pick(HOSTING) : city, bern(0.85) ? 'hosting' : 'residential', bern(0.9), s));
  } else if (kind === 'mfa_fatigue') {
    if (bern(0.9)) ev.push(['P', -1, Math.round(uni(3, 14))]);
    ev.push(signIn(0, city, bern(0.5) ? 'hosting' : 'residential', bern(0.85)));
  } else if (kind === 'helpdesk_reset') {
    ev.push(['M', -2, pick(['Authenticator app', 'Phone (SMS)'])]);
    ev.push(signIn(0, bern(0.6) ? pick(US_TRAVEL) : city, bern(0.4) ? 'hosting' : 'residential', bern(0.9)));
  } else {
    ev.push(signIn(0, bern(0.6) ? city : pick(US_TRAVEL), bern(0.6) ? 'hosting' : 'residential', bern(0.88)));
  }
  if (bern(0.25)) ev.push(['M', Math.round(uni(3, 20)), 'Authenticator app']);
  if (bern(0.62)) ev.push(['R', Math.round(uni(4, 40)), pick(['.', '..', ' ', 'RSS', 'x']), bern(0.85) ? 1 : 0, pick(['RSS Subscriptions', 'Archive', 'Conversation History', 'Deleted Items']), 1]);
  if (bern(0.38)) ev.push(['X', Math.round(uni(20, 180)), Math.round(uni(30, 600))]);
  return { kind, ev };
}

// ------------------------------------------------------------ timeline
const WEEKS = 26, OFFSITE_WEEK = 23; // weeks start Monday; week 1 = 11 May 2026, week 23 = 12 Oct 2026
const findings = []; let fid = 0;
function finding(w, a, ev, y, kind, extra = {}) {
  ev.sort((p, q) => p[1] - q[1]);
  // place the finding inside its week, during the account's waking hours mostly
  const day = Math.floor(rnd() * 7);
  const hourLocal = extra.hour ?? (y ? uni(0, 24) : weighted([[uni(7, 19), 0.8], [uni(0, 24), 0.2]]));
  const tz = cities[accounts[a].home].tz;
  const t = Math.round(((w - 1) * 7 + day) * 1440 + (hourLocal - tz) * 60);
  findings.push({ id: 'F-' + (10000 + fid++), w, t, a, y, k: kind, ev,
    d: +Math.exp(Math.log(4) + 0.6 * randn()).toFixed(2), // audit-log delay (min), median 4 (assumption)
    z: +randn().toFixed(3), ...extra });
}
for (let w = 1; w <= WEEKS; w++) {
  for (const g of ['exec', 'travel', 'other']) {
    const n = poisson(GROUP_RATE[g] * byGroup[g].length);
    for (let i = 0; i < n; i++) { const a = pick(byGroup[g]); let type = weighted(BENIGN_MIX[g]);
      if (type === 'vpn' && !accounts[a].vpn && rnd() < 0.85) type = weighted([['new_device', 0.5], ['push', 0.2], ['phone', 0.3]]);
      finding(w, a, benign(type, accounts[a]), 0, type); }
  }
  const nAto = poisson(4.2);
  for (let i = 0; i < nAto; i++) {
    const g = weighted([['exec', 0.4], ['travel', 0.25], ['other', 0.35]]); // BEC crews favour finance (assumption)
    const a = pick(byGroup[g]); const { kind, ev } = takeover(accounts[a]);
    finding(w, a, ev, 1, kind);
  }
  if (w === OFFSITE_WEEK) {
    // Sales kickoff in Lisbon, Tue-Thu: conference Wi-Fi egresses through a cloud proxy (hosting ASN),
    // phones roam between Wi-Fi and cellular mid-session, some reps set up new phones at the event.
    const reps = byGroup.travel.filter(i => accounts[i].dept === 'Sales');
    for (let i = 0; i < 95; i++) {
      const a = pick(reps);
      const ev = benign('travel', accounts[a], { city: C.Lisbon, hosting: 0.9, twoIps: 0.6, newDev: 0.35, glitch: 0.5, secondAsn: 'hosting' });
      ev.sort((p, q) => p[1] - q[1]);
      const day = 1 + Math.floor(rnd() * 3);
      const t = Math.round(((w - 1) * 7 + day) * 1440 + (uni(7, 23) - 1) * 60);
      findings.push({ id: 'F-' + (10000 + fid++), w, t, a, y: 0, k: 'offsite', ev,
        d: +Math.exp(Math.log(4) + 0.6 * randn()).toFixed(2), z: +randn().toFixed(3) });
    }
  }
}
findings.sort((p, q) => p.t - q.t);

const world = {
  meta: { tenant: 'northwind.example', seed: SEED, epoch: '2026-05-11T00:00:00Z', weeks: WEEKS, mailboxes: N_ACCT,
    events: [{ week: OFFSITE_WEEK, label: 'Sales kickoff, Lisbon', start: '2026-10-13', end: '2026-10-15', group: 'travel' }],
    generated: 'scripts/generate.mjs' },
  os: OS, ipNets: { h: '198.51.100.', m: '192.0.2.', r: '203.0.113.', c: '203.0.113.' }, cities, accounts, findings,
};
writeFileSync(new URL('../data/tenant.json', import.meta.url), JSON.stringify(world));
const atos = findings.filter(f => f.y).length;
console.log(`accounts ${N_ACCT}, findings ${findings.length}, takeovers ${atos}, bytes ${JSON.stringify(world).length}`);
