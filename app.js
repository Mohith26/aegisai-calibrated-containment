import * as K from './src/containment.js';

// ------------------------------------------------------------------ state
const LS = 'aegis.containment.v1';
const DEFAULTS = { mode: 'shadow', alphaInv: 200, conf: 95, guard: true, coverage: 'business', feedback: {}, approvedAt: null, group: 'travel' };
const S = { ...DEFAULTS, ...safeParse(localStorage.getItem(LS)) };
function safeParse(s) { try { return JSON.parse(s) || {}; } catch { return {}; } }
function save() { const { mode, alphaInv, conf, guard, coverage, feedback, approvedAt, group } = S; localStorage.setItem(LS, JSON.stringify({ mode, alphaInv, conf, guard, coverage, feedback, approvedAt, group })); }

let W = null, P = null; const memo = new Map();
const $ = s => document.querySelector(s);
const view = $('#view'), side = $('#side'), mainEl = $('#main');
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmtInt = n => n.toLocaleString('en-US');
const pct = (x, d = 1) => (x * 100).toFixed(d) + '%';
const TENANT_TZ = -5; // SOC in Chicago

// ------------------------------------------------------------------ boot
async function boot() {
  try {
    const t0 = performance.now();
    const res = await fetch('data/tenant.json');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    W = await res.json();
    K.EPOCH_MS; // epoch is fixed in the module (2026-05-11 UTC) and matches meta.epoch
    P = K.prepare(W);
    P.acctFindings = new Map();
    for (const r of P.rows) { const l = P.acctFindings.get(r.f.a) || []; l.push(r); P.acctFindings.set(r.f.a, l); }
    P.byId = new Map(P.rows.map(r => [r.f.id, r]));
    console.info(`[aegis-demo] ready in ${Math.round(performance.now() - t0)} ms: ${W.findings.length} findings`);
    window.addEventListener('hashchange', route);
    route();
  } catch (e) {
    view.innerHTML = `<div class="err" role="alert"><b>Couldn't load findings</b>The tenant data did not load (${esc(e.message)}). <p><button class="btn" onclick="location.reload()">Try again</button></p></div>`;
  }
}

// ------------------------------------------------------------------ policy + replay (memoised)
function alphaByGroup() { const a = 1 / S.alphaInv; return { exec: a, travel: a, other: a }; }
function policy() {
  const key = `pol|${S.alphaInv}|${S.conf}`;
  if (!memo.has(key)) memo.set(key, K.calibratePolicy(P.cal, alphaByGroup(), 1 - S.conf / 100));
  return memo.get(key);
}
function run(mode = S.mode === 'off' ? 'off' : 'calibrated', guard = S.guard, extra = {}) {
  const key = `run|${S.alphaInv}|${S.conf}|${mode}|${guard}|${S.coverage}|${JSON.stringify(S.feedback)}|${JSON.stringify(extra)}`;
  if (!memo.has(key)) {
    const r = K.replay(P.test, { policy: policy(), mode, guard, feedback: S.feedback, coverage: S.coverage, ...extra });
    r.byId = new Map(r.decisions.map(d => [d.id, d]));
    memo.set(key, r);
  }
  return memo.get(key);
}

// ------------------------------------------------------------------ time helpers
const DAY = 1440;
function dt(tMin, tz) { return new Date(K.EPOCH_MS + (tMin + tz * 60) * 60000); }
function hhmm(tMin, tz) { const d = dt(tMin, tz); return String(d.getUTCHours()).padStart(2, '0') + ':' + String(d.getUTCMinutes()).padStart(2, '0'); }
function hhmmss(tMin, tz) { const d = dt(tMin, tz); return hhmm(tMin, tz) + ':' + String(d.getUTCSeconds()).padStart(2, '0'); }
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], DOW = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
function dayLabel(tMin, tz) { const d = dt(tMin, tz); return `${DOW[d.getUTCDay()]} ${MON[d.getUTCMonth()]} ${d.getUTCDate()}`; }
function weekRange(w) { const s = (w - 1) * 7 * DAY, e = s + 6 * DAY; const a = dt(s, 0), b = dt(e, 0); return `${MON[a.getUTCMonth()]} ${a.getUTCDate()} – ${MON[b.getUTCMonth()]} ${b.getUTCDate()}`; }
const initials = n => n.split(' ').map(x => x[0]).join('').slice(0, 2).toUpperCase();
const AVC = ['#5f6368', '#3c4043', '#6b5b95', '#2f6f73', '#7a5c3e', '#46535f'];
const avColor = () => '#5f6368';

const FNAME = { impossible_travel: 'impossible travel', new_country: 'new country', new_country_nontraveler: 'new country', first_seen_device: 'first-seen device', hosting_unusual: 'hosting provider', session_two_ips: 'session from 2 IPs', mfa_push_burst: 'push denials', mfa_method_added: 'new MFA method', rule_created: 'new rule', rule_hidden: 'hidden rule', rule_payment_terms: 'payment terms', first_rule_ever: 'first rule', internal_send_burst: 'internal sends', off_hours: 'off hours' };
// ------------------------------------------------------------------ signals
function signals(r) {
  const { f, a } = r;
  const { x, km, minutes } = K.featurize(f, a, W);
  const tags = [];
  const push = (label, strong) => tags.push({ label, strong });
  if (x[0]) push(`${fmtInt(Math.round(km / 100) * 100)} km in ${minutes} min`, true);
  if (x[6]) push('Session from 2 IPs', true);
  if (x[4]) push('Hosting provider', true);
  if (x[10]) push('Hidden rule', true); else if (x[9]) push('New rule', false);
  if (x[7]) { const p = f.ev.find(e => e[0] === 'P'); push(`${p[2]} push denials`, true); }
  if (x[3]) push('First-seen device', false);
  if (x[8]) push('New MFA method', false);
  if (x[11]) push('Payment terms', false);
  if (x[13]) { const xx = f.ev.find(e => e[0] === 'X'); push(`${xx[2]} internal sends`, false); }
  if (x[1]) { const s = f.ev.slice(1).find(e => e[0] === 'S' && W.cities[e[2]].country !== W.cities[a.home].country); if (s) push(`New country · ${W.cities[s[2]].country}`, false); }
  if (x[5]) push('Known VPN', false);
  if (!tags.length) push('Normal', false);
  return { x, km, minutes, tags };
}
function statusOf(score, label) {
  if (label === 0 && score >= K.LIKELY) return { k: 'likely', t: 'Likely takeover' };
  if (score >= K.LIKELY) return { k: 'likely', t: 'Likely takeover' };
  if (score >= 0.05) return { k: 'watch', t: 'Watching' };
  return { k: 'normal', t: 'Normal' };
}

// ------------------------------------------------------------------ router
function parseHash() {
  const h = location.hash.replace(/^#\/?/, '') || 'findings';
  const [path, qs] = h.split('?');
  const parts = path.split('/');
  return { page: parts[0], id: parts[1], q: Object.fromEntries(new URLSearchParams(qs || '')) };
}
function setHash(page, q = {}, replace = false) {
  const s = new URLSearchParams(Object.entries(q).filter(([, v]) => v !== undefined && v !== null && v !== '')).toString();
  const h = '#/' + page + (s ? '?' + s : '');
  if (replace) history.replaceState(null, '', h); else location.hash = h;
}
let current = null;
function route() {
  const r = parseHash(); current = r;
  document.querySelectorAll('.nav a').forEach(a => a.classList.toggle('on', a.dataset.nav === (r.page === 'finding' ? 'findings' : r.page)));
  side.hidden = true; mainEl.classList.remove('with-side');
  modePill();
  if (r.page === 'findings') renderFindings(r.q);
  else if (r.page === 'finding') renderFinding(r.id);
  else if (r.page === 'containment') renderContainment(r.q);
  else if (r.page === 'accounts') renderAccounts(r.q);
  else renderPlaceholder(r.page);
  view.scrollTop = 0;
}
function modePill() {
  const el = $('#mode-pill');
  const m = S.mode;
  el.className = 'mode-pill ' + m;
  el.innerHTML = `<b></b>${m === 'live' ? 'Containment live' : m === 'shadow' ? 'Shadow mode' : 'Containment off'}`;
  const R = run();
  $('#nav-cnt').textContent = R.decisions.filter(d => d.w === 26 && d.max >= K.LIKELY).length;
}

// ------------------------------------------------------------------ findings list
const TABS = [['all', 'All'], ['likely', 'Likely takeover'], ['contained', 'Contained'], ['review', 'Needs review'], ['legit', 'Legitimate']];
let listCursor = 0, listIds = [];
function renderFindings(q) {
  const week = Math.min(26, Math.max(19, +(q.week || 26)));
  const tab = q.tab || 'all', sort = q.sort || 'score', dir = q.dir || 'desc', query = (q.q || '').toLowerCase();
  $('#q').value = q.q || '';
  const R = run();
  const live = S.mode === 'live', shadow = S.mode === 'shadow';
  const rows = P.test.filter(r => r.f.w === week).map(r => ({ r, d: R.byId.get(r.f.id) }));
  const cnt = {
    all: rows.length,
    likely: rows.filter(x => x.r.max >= K.LIKELY).length,
    contained: rows.filter(x => x.d.auto).length,
    review: rows.filter(x => x.d.review).length,
    legit: rows.filter(x => !x.d.y && x.r.max >= K.LIKELY).length,
  };
  let list = rows.filter(x => {
    if (query && !(x.r.a.n.toLowerCase().includes(query) || x.r.a.e.includes(query))) return false;
    if (tab === 'likely') return x.r.max >= K.LIKELY;
    if (tab === 'contained') return x.d.auto;
    if (tab === 'review') return x.d.review;
    if (tab === 'legit') return !x.d.y && x.r.max >= K.LIKELY;
    return x.r.max >= 0.1 || tab !== 'all' ? true : true;
  });
  const key = { time: x => x.r.f.t, score: x => x.r.max, account: x => x.r.a.n }[sort] || (x => x.r.max);
  list.sort((p, q2) => { const a = key(p), b = key(q2); return (a < b ? -1 : a > b ? 1 : 0) * (dir === 'asc' ? 1 : -1); });
  const wk = R.decisions.filter(d => d.w === week);
  const atos = wk.filter(d => d.y), auto = atos.filter(d => d.auto), wrong = wk.filter(d => d.wrong);
  const autoT = auto.map(d => d.tAuto).sort((a, b) => a - b);
  const paused = Object.entries(R.paused).filter(([, t]) => t !== null && Math.floor(t / (7 * DAY)) + 1 <= week);
  const meta = W.meta.events.find(e => e.week === week);
  view.innerHTML = `
  <div class="ph"><div><h1>Findings</h1>
    <div class="sub">Replay · week of ${weekRange(week)} · <b>${fmtInt(rows.length)}</b> findings · containment <b>${S.mode === 'live' ? 'live' : S.mode === 'shadow' ? 'in shadow mode' : 'off'}</b>${meta ? ` · ${esc(meta.label)}` : ''}</div></div>
    <div class="ph-r">
      <div class="stepper" role="group" aria-label="Week"><button id="wk-prev" aria-label="Previous week" ${week <= 19 ? 'disabled' : ''}><svg viewBox="0 0 24 24"><path d="m15 18-6-6 6-6"/></svg></button><span>${weekRange(week)}, 2026</span><button id="wk-next" aria-label="Next week" ${week >= 26 ? 'disabled' : ''}><svg viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg></button></div>
      <button class="btn" id="exp-week"><svg viewBox="0 0 24 24"><path d="M12 4v11m0 0-4-4m4 4 4-4M5 20h14"/></svg>Export CSV</button>
    </div></div>
  <div class="stats">
    <div class="stat"><em>Likely takeovers</em><b>${cnt.likely}</b><span>${atos.length} confirmed by analysts</span></div>
    <div class="stat"><em>${shadow ? 'Would contain automatically' : 'Contained automatically'}</em><b>${S.mode === 'off' ? '—' : auto.length}<small>${S.mode === 'off' ? '' : 'of ' + atos.length}</small></b><span>${autoT.length ? 'median ' + K.fmtDuration(K.quantile(autoT, .5)) + ' after first sign-in' : S.mode === 'off' ? 'Automated containment is off' : 'none this week'}</span></div>
    <div class="stat"><em>Waiting for an analyst</em><b>${cnt.review}</b><span>score ≥ ${K.LIKELY} and below the threshold</span></div>
    <div class="stat"><em>Wrong revocations</em><b>${S.mode === 'off' ? '—' : wrong.length}</b><span>${paused.length ? paused.map(([g, t]) => K.GROUP_LABEL[g] + ' paused since ' + dayLabel(t, TENANT_TZ).slice(4)).join(', ') : 'limit 1 in ' + fmtInt(S.alphaInv) + ' legitimate findings'}</span></div>
  </div>
  <div class="tabs" role="tablist">${TABS.map(([k, l]) => `<button role="tab" aria-selected="${k === tab}" class="${k === tab ? 'on' : ''}" data-tab="${k}">${l}<i>${cnt[k]}</i></button>`).join('')}</div>
  ${list.length ? `<table class="ft"><thead><tr>
    ${th('time', 'Time', sort, dir)}${th('account', 'Account', sort, dir)}<th>Signals</th>${th('score', 'Score', sort, dir)}<th>Status</th><th>Containment</th></tr></thead>
    <tbody>${list.map((x, i) => rowHtml(x, i, live, shadow)).join('')}</tbody></table>`
    : `<div class="empty"><b>No findings match</b>${query ? `Nothing for “${esc(q.q)}” in this week.` : 'Nothing in this view for the selected week.'}</div>`}`;
  listIds = list.map(x => x.r.f.id); listCursor = Math.min(listCursor, Math.max(0, listIds.length - 1));
  const go = w => setHash('findings', { ...q, week: w });
  $('#wk-prev').onclick = () => go(week - 1); $('#wk-next').onclick = () => go(week + 1);
  view.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => setHash('findings', { ...q, tab: b.dataset.tab }));
  view.querySelectorAll('th[data-sort]').forEach(h => h.onclick = () => setHash('findings', { ...q, sort: h.dataset.sort, dir: sort === h.dataset.sort && dir === 'desc' ? 'asc' : 'desc' }));
  view.querySelectorAll('tr.row').forEach(tr => tr.onclick = () => setHash('finding/' + tr.dataset.id, { from: week }));
  $('#exp-week').onclick = () => exportCSV(R.decisions.filter(d => d.w === week), `aegis-findings-week-${week}.csv`);
  highlightCursor();
}
function th(k, label, sort, dir) { return `<th data-sort="${k}" ${sort === k ? `aria-sort="${dir === 'asc' ? 'ascending' : 'descending'}"` : ''}><span>${label}</span></th>`; }
function rowHtml({ r, d }, i, live, shadow) {
  const sg = signals(r), st = statusOf(r.max), a = r.a;
  const tags = sg.tags.slice(0, 4).map(t => `<span class="tag ${t.strong && r.max >= K.LIKELY ? 'flag' : ''}">${esc(t.label)}</span>`).join('') + (sg.tags.length > 4 ? `<span class="tag">+${sg.tags.length - 4}</span>` : '');
  let cn = '<span class="cn">—<small>no action</small></span>';
  if (d.auto) {
    const lbl = shadow ? 'Would revoke sessions' : 'Sessions revoked';
    cn = `<span class="cn"><i class="dot ${d.wrong ? 'wrong' : shadow ? 'would' : 'auto'}"></i>${lbl}<small>${d.wrong ? 'user was legitimate' : '+' + K.fmtDuration(d.tAuto) + ' after sign-in'}</small></span>`;
  } else if (d.review) {
    cn = `<span class="cn"><i class="dot"></i>Analyst review<small>${d.y ? 'contained +' + K.fmtDuration(d.tAnalyst) : 'closed as legitimate'}</small></span>`;
  }
  return `<tr class="row" data-id="${r.f.id}" tabindex="-1">
    <td><time>${hhmm(r.f.t, TENANT_TZ)}<small>${dayLabel(r.f.t, TENANT_TZ)}</small></time></td>
    <td><div class="acct"><span class="av" style="background:${avColor(a.n)}">${initials(a.n)}</span><div><b>${esc(a.n)}</b><small>${esc(a.e)} · ${esc(a.dept)}</small></div></div></td>
    <td><div class="tags">${tags}</div></td>
    <td><span class="score">${r.max.toFixed(2)}</span><span class="bar"><i style="width:${(r.max * 100).toFixed(0)}%"></i></span></td>
    <td><span class="st ${st.k}">${st.t}</span></td>
    <td>${cn}</td></tr>`;
}
function highlightCursor() {
  view.querySelectorAll('tr.row').forEach((tr, i) => tr.classList.toggle('cur', i === listCursor));
  const cur = view.querySelectorAll('tr.row')[listCursor]; if (cur) cur.scrollIntoView({ block: 'nearest' });
}

// ------------------------------------------------------------------ finding detail
const OSN = i => W.os[i];
function evDesc(e, f, a, firstSeenSessions) {
  const c = W.cities[e[2]];
  if (e[0] === 'S') {
    const ip = W.ipNets[e[4]] + e[3], [os, br] = OSN(e[6]);
    const net = e[4] === 'h' ? 'hosting provider' : e[4] === 'm' ? 'mobile network' : '';
    const replay = firstSeenSessions.has(e[7]) && firstSeenSessions.get(e[7]) !== e[3];
    if (!firstSeenSessions.has(e[7])) firstSeenSessions.set(e[7], e[3]);
    const dev = e[5] ? 'first-seen device' : 'known ' + (os === 'iOS' || os === 'Android' ? 'phone' : 'laptop');
    const txt = `Sign-in, ${c.name}, ${dev}${net ? ', ' + net : ''}.${e[1] < 0 ? ' MFA satisfied.' : replay ? ' Same session token as an earlier sign-in.' : ''}`;
    return { txt, small: `${ip} · ${os} / ${br}`, replay };
  }
  if (e[0] === 'P') return { txt: `${e[2]} MFA push prompts denied, then one approved.`, small: 'Microsoft Authenticator' };
  if (e[0] === 'M') return { txt: `New MFA method registered: ${e[2]}.`, small: 'Security info' };
  if (e[0] === 'R') return { txt: `New inbox rule named “${e[2]}”: ${e[3] ? 'mail containing invoice, payment or wire' : 'matching mail'} moved to ${e[4]}${e[5] ? ' and marked read' : ''}.`, small: 'Mailbox rule' };
  if (e[0] === 'X') return { txt: `${fmtInt(e[2])} internal emails sent in 10 minutes.`, small: 'Outbound to colleagues' };
  return { txt: '', small: '' };
}
function renderFinding(id) {
  const r = P.byId.get(id);
  if (!r) { view.innerHTML = `<div class="empty"><b>Finding not found</b>${esc(id || '')} is not in this tenant. <p><a class="btn" href="#/findings">Back to findings</a></p></div>`; return; }
  const inReplay = r.f.w >= 19;
  const R = run(); const d = inReplay ? R.byId.get(id) : null;
  const pol = policy(), cert = pol[r.g];
  const a = r.a, home = W.cities[a.home], tz = home.tz;
  const sg = signals(r), st = statusOf(r.max);
  const label = S.feedback[id] ? (S.feedback[id] === 'ato' ? 1 : 0) : r.f.y;
  const sess = new Map();
  const tAuto = d && d.auto ? d.tAuto : null;
  const items = r.f.ev.map((e, i) => {
    const ds = evDesc(e, r.f, a, sess);
    let tag = 'Normal', flag = false;
    if (e[0] === 'S' && i > 0) {
      const kmE = K.haversineKm(W.cities[r.f.ev[0][2]], W.cities[e[2]]), minE = Math.max(1, e[1] - r.f.ev[0][1]);
      if (kmE > 500 && kmE / (minE / 60) > 900) { tag = `${fmtInt(Math.round(kmE / 100) * 100)} km in ${minE} min`; flag = true; }
      else if (ds.replay) { tag = 'Session replayed'; flag = true; }
      else if (e[4] === 'h' && !a.vpn) { tag = 'Hosting provider'; flag = true; }
      else if (e[5]) { tag = 'First-seen device'; flag = true; }
      else if (W.cities[e[2]].country !== home.country) tag = 'New country';
    }
    if (e[0] === 'P') { tag = `${e[2]} denials`; flag = e[2] >= 3; }
    if (e[0] === 'M') { tag = 'New MFA method'; flag = true; }
    if (e[0] === 'R') { tag = K.HIDDEN_ACTIONS.has(e[4]) && e[5] ? 'Hidden rule' : 'New rule'; flag = tag === 'Hidden rule'; }
    if (e[0] === 'X') { tag = 'Internal burst'; flag = e[2] >= 25; }
    const prevented = tAuto !== null && label && e[1] > tAuto && (e[0] === 'R' || e[0] === 'X' || e[0] === 'M');
    return { t: r.f.t + e[1], rel: e[1], ...ds, tag: prevented ? 'Prevented' : tag, flag: prevented ? false : flag, prevented };
  });
  if (tAuto !== null && S.mode !== 'off') {
    items.push({ t: r.f.t + tAuto, rel: tAuto, sys: true, txt: S.mode === 'shadow' ? 'Aegis would revoke all sessions (shadow mode).' : 'Aegis revoked all sessions in Entra ID and deleted the rule.',
      small: `score ${K.firstCross(r.run, cert.threshold) !== null ? r.run.find(x => x.s >= cert.threshold).s.toFixed(2) : ''} ≥ ${cert.threshold.toFixed(3)} certified for ${K.GROUP_LABEL[r.g]}`, tag: S.mode === 'shadow' ? 'Shadow' : 'Contained', flag: true });
    items.sort((p, q) => p.rel - q.rel);
  }
  const t0 = items[0].t, t1 = items[items.length - 1].t;
  const from = parseHash().q.from;
  view.innerHTML = `
    <div class="crumb"><a href="#/findings${from ? '?week=' + from : ''}">Findings</a><span>/</span><span>${esc(id)}</span>${inReplay ? '' : '<span>· calibration window</span>'}</div>
    <div class="d-acct"><span class="av" style="background:${avColor(a.n)}">${initials(a.n)}</span><div><b>${esc(a.n)}</b><small>${esc(a.e)} · ${esc(a.dept)} · ${esc(K.GROUP_LABEL[r.g])}</small></div><span class="st ${label === 0 && S.feedback[id] ? 'legit' : st.k}">${label === 0 && S.feedback[id] ? 'Marked legitimate' : st.t}</span></div>
    <div class="d-h"><span>${dayLabel(r.f.t, tz)} · activity (${home.name} time)</span><span>${hhmm(t0, tz)} to ${hhmm(t1, tz)}</span></div>
    <ul class="ev">${items.map(it => `<li class="${it.prevented ? 'prevented' : ''} ${it.sys ? 'sys' : ''}"><time>${it.sys ? hhmmss(it.t, tz).slice(0, 5) : hhmm(it.t, tz)}</time><p>${esc(it.txt)}<small>${esc(it.small)}</small></p><span class="tag ${it.flag ? 'flag' : ''}">${esc(it.tag)}</span></li>`).join('')}</ul>
    ${d ? timelineCard(r, d, label) : `<div class="tl"><h3>Calibration example</h3><p>This finding is in the calibration window (weeks 11 to 18). Its score is one of the ${fmtInt(cert.n)} legitimate or ${cert.nAto} takeover scores used to certify the ${K.GROUP_LABEL[r.g]} threshold.</p></div>`}`;
  side.hidden = false; mainEl.classList.add('with-side');
  renderSide(r, d, sg, label, cert);
}
function timelineCard(r, d, label) {
  const steps = r.f.ev.filter(e => e[1] > 0 && 'RXM'.includes(e[0]));
  const end = Math.max(60, ...(d.tAnalyst ? [d.tAnalyst] : []), ...steps.map(e => e[1]), d.tAuto || 0) * 1.08;
  const Wd = 880, H = 104, x = t => 20 + (Wd - 40) * Math.sqrt(Math.max(0, t) / end);
  const ticks = [0, 5, 15, 30, 60, 120, 240, 480, 960, 1920].filter(t => t <= end);
  const lbl = { R: 'Inbox rule', X: 'Internal sends', M: 'MFA method' };
  const svg = `<svg viewBox="0 0 ${Wd} ${H}" class="chart" role="img" aria-label="Containment timeline">
    <line x1="20" x2="${Wd - 20}" y1="46" y2="46" stroke="#d7dbe0"/>
    ${ticks.map(t => `<line x1="${x(t)}" x2="${x(t)}" y1="42" y2="50" stroke="#d7dbe0"/><text x="${x(t)}" y="66" text-anchor="${t ? 'middle' : 'start'}">${t === 0 ? 'sign-in' : t < 60 ? '+' + t + 'm' : '+' + t / 60 + 'h'}</text>`).join('')}
    <circle cx="${x(0)}" cy="46" r="4" fill="#1f1f23"/>
    ${steps.map((e, i) => `<rect x="${x(e[1]) - 4}" y="${42}" width="8" height="8" transform="rotate(45 ${x(e[1])} 46)" fill="${d.auto && label && e[1] > d.tAuto ? '#fff' : '#ff6d6d'}" stroke="#ff6d6d" stroke-width="1.5"/><text x="${x(e[1])}" y="${84 + (i % 2) * 14}" text-anchor="middle" fill="#d93838">${lbl[e[0]]}${d.auto && label && e[1] > d.tAuto ? ' (prevented)' : ''}</text>`).join('')}
    ${d.auto ? `<line x1="${x(d.tAuto)}" x2="${x(d.tAuto)}" y1="18" y2="58" stroke="#08080a" stroke-width="2"/><text x="${x(d.tAuto) + 5}" y="16" fill="#08080a" style="font-weight:600">${S.mode === 'shadow' ? 'Aegis would revoke' : 'Aegis revokes'} +${K.fmtDuration(d.tAuto)}</text>` : ''}
    ${d.tAnalyst !== null && label ? `<line x1="${x(d.tAnalyst)}" x2="${x(d.tAnalyst)}" y1="30" y2="58" stroke="#9e9ea7" stroke-width="2" stroke-dasharray="3 3"/><text x="${Math.min(x(d.tAnalyst), Wd - 60)}" y="${d.auto ? 30 : 16}" text-anchor="middle">analyst +${K.fmtDuration(d.tAnalyst)}</text>` : ''}
  </svg>`;
  const prevented = d.auto && label ? steps.filter(e => e[1] > d.tAuto).length : 0;
  const msg = !label ? (d.auto ? 'This legitimate finding was revoked: the user signs in again with MFA. It counts against the wrong-revocation limit and feeds the guard.' : 'Legitimate activity. No sessions were revoked.')
    : d.auto ? `Contained ${K.fmtDuration(d.tAuto)} after the first suspicious sign-in${d.tAnalyst !== null ? `, ${K.fmtDuration(d.tAnalyst - d.tAuto)} before an analyst would have acted` : ''}. ${prevented} of ${steps.length} attacker step${steps.length === 1 ? '' : 's'} prevented.`
      : d.tAnalyst !== null ? `Score stayed below the certified threshold, so this one waited for an analyst (+${K.fmtDuration(d.tAnalyst)}).` : 'Score never reached the review bar; this takeover was not caught in time.';
  return `<div class="tl"><h3>Containment timeline</h3><p>${esc(msg)}</p>${svg}</div>`;
}
function renderSide(r, d, sg, label, cert) {
  const a = r.a, x = sg.x, f = r.f;
  const rule = f.ev.find(e => e[0] === 'R'), push = f.ev.find(e => e[0] === 'P'), xs = f.ev.find(e => e[0] === 'X');
  const sig = [
    ['Travel', x[0] ? `${fmtInt(Math.round(sg.km / 100) * 100)} km away. Faster than travel.` : x[1] ? 'New country, plausible travel time.' : 'No unusual travel.', x[0] || x[1]],
    ['Device', x[3] ? 'First-seen device for this account.' : 'Known device.', x[3]],
    ['Network', x[4] ? 'Hosting provider. Never signs in from one.' : x[5] ? 'Hosting provider, but a known VPN habit.' : x[15] ? 'Mobile carrier network.' : 'Residential or office network.', x[4]],
    ['Session', x[6] ? 'Same session token used from two IPs.' : 'No session reuse.', x[6]],
    ['MFA', x[7] ? `${push[2]} push prompts denied before approval.` : x[8] ? 'New MFA method registered.' : 'No MFA changes.', x[7] || x[8]],
    ['Mailbox rules', rule ? (x[10] ? `Hidden rule moves ${rule[3] ? 'invoice and payment ' : ''}mail.` : 'New rule, files mail normally.') : 'No rule changes.', !!rule],
    ['Account history', rule && !a.rules ? 'This account has never created a rule.' : a.traveler ? `Travels often (${a.dept}).` : a.vpn ? 'Uses a VPN regularly.' : 'Signs in from the office or home.', rule && !a.rules],
    ['Internal sends', xs ? `${fmtInt(xs[2])} emails to colleagues in 10 minutes.` : 'No unusual sending.', x[13]],
  ];
  // contributions (logit units) for the explanation line
  const contrib = K.FEATURES.map((n, j) => ({ n, v: P.model.w[j] * x[j] })).filter(c => c.v > 0.05).sort((p, q) => q.v - p.v).slice(0, 3);
  const st = statusOf(r.max);
  const isLikely = r.max >= K.LIKELY;
  let ac = '';
  if (!cert.certified) ac = `<div class="ac"><span class="big none">No automatic action</span><span class="math">${esc(K.GROUP_LABEL[r.g])} has ${fmtInt(cert.n)} legitimate findings; 1 in ${fmtInt(S.alphaInv)} needs ${fmtInt(cert.minN)} to certify.</span></div>`;
  else if (!d) ac = `<div class="ac"><span class="big none">Calibration data</span><span class="math">certified threshold ${cert.threshold.toFixed(3)} · score ${r.max.toFixed(3)}</span></div>`;
  else if (S.mode === 'off') ac = `<div class="ac"><span class="big none">Automated containment is off</span><span class="math">score ${r.max.toFixed(3)} · threshold would be ${cert.threshold.toFixed(3)}</span></div>`;
  else if (d.auto) ac = `<div class="ac"><span class="big ${S.mode === 'shadow' ? 'would' : !label ? 'wrong' : ''}">${S.mode === 'shadow' ? 'Would revoke sessions' : 'Sessions revoked automatically'} · ${hhmmss(f.t + d.tAuto, W.cities[a.home].tz)}</span><span class="math">score ${r.run.find(z => z.s >= cert.threshold).s.toFixed(3)} ≥ ${cert.threshold.toFixed(3)}, certified for ${esc(K.GROUP_LABEL[r.g])}: wrong revocations ≤ 1 in ${fmtInt(S.alphaInv)} legitimate findings, ${S.conf}% confidence (${fmtInt(cert.n)} findings, ${cert.k} above).</span></div>`;
  else {
    const pausedAt = run().paused[r.g];
    const why = pausedAt !== null && pausedAt <= f.t ? `Guard paused ${esc(K.GROUP_LABEL[r.g])} on ${dayLabel(pausedAt, TENANT_TZ)}; review only until recalibrated.` : `score ${r.max.toFixed(3)} < ${cert.threshold.toFixed(3)} certified for ${esc(K.GROUP_LABEL[r.g])}`;
    ac = `<div class="ac"><span class="big none">${isLikely ? 'Sent to an analyst' : 'No action'}</span><span class="math">${why}</span></div>`;
  }
  const fb = S.feedback[f.id];
  side.innerHTML = `
    <div class="side-h"><b>Aegis</b><span>Complete</span></div><div class="side-prog"></div>
    <ul class="sig">${sig.filter(([k, , on]) => on || k === 'Account history').map(([k, v, on]) => `<li class="${on ? 'done' : 'idle'}"><div><em>${k}</em><div>${esc(v)}</div></div></li>`).join('')}</ul>
    <div class="vd ${isLikely ? '' : 'benign'}"><b>${isLikely ? 'Likely account takeover' : st.k === 'watch' ? 'Watching this account' : 'Normal activity'}</b>
      <small>${isLikely ? 'Weak alone, decisive together.' : 'Signals present but weak together.'} Score ${r.max.toFixed(2)}${contrib.length ? ' · ' + contrib.map(c => FNAME[c.n] || c.n).join(', ') : ''}</small>
      ${isLikely ? `<p class="k">Recommended steps</p><ol>
        <li class="${d && d.auto && S.mode === 'live' ? 'doneStep' : ''}">Revoke sessions in your identity provider.</li>
        ${rule ? `<li class="${d && d.auto && S.mode === 'live' ? 'doneStep' : ''}">Delete the rule.</li>` : ''}
        ${x[8] ? '<li>Remove the new MFA method.</li>' : ''}</ol>` : ''}
      <p class="k">Automated containment</p>${ac}
      ${d && d.auto ? `<div class="acts"><button class="btn ${fb === 'ato' ? 'dark' : ''}" data-fb="ato">${fb === 'ato' ? 'Takeover confirmed' : 'Confirm takeover'}</button><button class="btn ${fb === 'legit' ? 'dark' : ''}" data-fb="legit">${fb === 'legit' ? 'Marked legitimate' : 'Mark as legitimate'}</button>${fb ? '<button class="btn" data-fb="">Undo</button>' : ''}</div>
        <div class="fb">${fb ? 'Your label overrides the disposition in this replay and updates the guard.' : 'Labels feed the auto-pause guard for this group.'}</div>` : `<span class="note">${isLikely ? 'Your team acts in Entra ID, Okta or Google Workspace.' : ''}</span>`}
    </div>`;
  side.querySelectorAll('[data-fb]').forEach(b => b.onclick = () => {
    const v = b.dataset.fb; if (v) S.feedback[f.id] = v; else delete S.feedback[f.id];
    save(); memo.forEach((_, k) => k.startsWith('run|') && memo.delete(k));
    toast(v === 'legit' ? 'Recorded as a wrong revocation. Guard updated.' : v === 'ato' ? 'Takeover confirmed.' : 'Label removed.');
    route();
  });
}

// ------------------------------------------------------------------ containment page
const ALPHAS = [100, 200, 500, 1000], CONFS = [90, 95, 99];
function renderContainment(q) {
  let changed = false;
  if (q.a && ALPHAS.includes(+q.a) && +q.a !== S.alphaInv) { S.alphaInv = +q.a; changed = true; }
  if (q.c && CONFS.includes(+q.c) && +q.c !== S.conf) { S.conf = +q.c; changed = true; }
  if (q.g && K.GROUPS.includes(q.g)) S.group = q.g;
  if (q.guard !== undefined) S.guard = String(q.guard) !== '0';
  if (q.cov && ['business', '24x7'].includes(q.cov)) S.coverage = q.cov;
  if (changed && S.mode === 'live') S.mode = 'shadow';
  save();
  const pol = policy(), R = run(S.mode === 'off' ? 'calibrated' : 'calibrated'), M = R.metrics;
  const base = run('off'), fixed = run('fixed', false, { fixedThr: 0.9 }), noGuard = run('calibrated', false);
  const g = S.group, cg = pol[g];
  const groupsHtml = K.GROUPS.map(k => {
    const c = pol[k], bg = M.byGroup[k], accts = W.accounts.filter(x => x.g === k).length, pausedAt = R.paused[k];
    let stt = !c.certified ? '<span class="gst none">Not enough history</span>' : pausedAt !== null ? `<span class="gst paused">Paused ${dayLabel(pausedAt, TENANT_TZ).slice(4)}</span>` : S.mode === 'live' ? '<span class="gst live">Live</span>' : S.mode === 'shadow' ? '<span class="gst shadow">Shadow</span>' : '<span class="gst off">Off</span>';
    const weekly = c.n / 8;
    return `<tr class="g ${k === g ? 'sel' : ''}" data-g="${k}" tabindex="0" aria-label="${K.GROUP_LABEL[k]}">
      <td><b>${K.GROUP_LABEL[k]}</b><small>${fmtInt(accts)} accounts</small></td>
      <td class="num">${fmtInt(c.n)}<small>${c.nAto} takeovers</small></td>
      <td class="num">${c.certified ? c.threshold.toFixed(3) : '—'}<small>${c.certified ? c.k + ' legitimate above' : 'needs ' + fmtInt(c.minN)}</small></td>
      <td class="num">≤ ${pct(c.alpha, 2)}<small>${c.certified ? '≈ ' + (c.alpha * weekly).toFixed(1) + ' / week max' : 'review only'}</small></td>
      <td class="num">${c.certified ? pct(c.calTpr, 0) : '—'}<small>calibration weeks</small></td>
      <td class="num">${c.certified ? `${bg.auto} of ${bg.atos}` : '—'}<small>${bg.wrong} wrong of ${fmtInt(bg.legit)}</small></td>
      <td>${stt}</td></tr>`;
  }).join('');
  const lisbon = W.meta.events[0];
  const tripped = Object.entries(R.paused).filter(([, t]) => t !== null);
  const anyCert = K.GROUPS.some(k => pol[k].certified);
  view.innerHTML = `
  <div class="ph"><div><h1>Automated containment</h1><div class="sub">Account takeover · early access · certified on weeks ${P.calWeeks[0]} to ${P.calWeeks[1]}, replayed on weeks ${P.testWeeks[0]} to ${P.testWeeks[1]}</div></div>
    <div class="ph-r"><div class="seg" role="radiogroup" aria-label="Mode">${['off', 'shadow', 'live'].map(m => `<button role="radio" aria-checked="${S.mode === m}" class="${S.mode === m ? 'on' : ''}" data-mode="${m}" ${m !== 'off' && !anyCert ? 'disabled' : ''}>${m[0].toUpperCase() + m.slice(1)}</button>`).join('')}</div>
    <button class="btn dark" id="approve" ${!anyCert ? 'disabled' : ''}>${S.mode === 'live' ? 'Live since ' + new Date(S.approvedAt || Date.now()).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : 'Review and go live'}</button><button class="btn" id="exp-json"><svg viewBox="0 0 24 24"><path d="M12 4v11m0 0-4-4m4 4 4-4M5 20h14"/></svg>Policy JSON</button><button class="btn" id="exp-csv"><svg viewBox="0 0 24 24"><path d="M12 4v11m0 0-4-4m4 4 4-4M5 20h14"/></svg>Replay CSV</button></div></div>
  <p class="intro">Aegis revokes sessions on its own when a finding's score clears a threshold that is certified on this tenant's own history: the share of legitimate findings that get revoked stays under your limit, with a stated confidence, separately for each group. Everything below the threshold goes to your team, as today.</p>
  <div class="ctl">
    <label>Wrong revocations, at most<div class="seg">${ALPHAS.map(v => `<button data-a="${v}" class="${S.alphaInv === v ? 'on' : ''}" aria-pressed="${S.alphaInv === v}">1 in ${fmtInt(v)}</button>`).join('')}</div></label>
    <label>Confidence<div class="seg">${CONFS.map(v => `<button data-c="${v}" class="${S.conf === v ? 'on' : ''}" aria-pressed="${S.conf === v}">${v}%</button>`).join('')}</div></label>
    <label>Action<span class="chip">Revoke sessions + delete hidden rule</span></label>
    <label>Auto-pause guard<span class="swrap"><button class="switch" role="switch" aria-checked="${S.guard}" id="guard" aria-label="Auto-pause guard"></button>${S.guard ? 'On' : 'Off'}</span></label>
    <label>Analyst coverage (replay)<div class="seg">${[['business', 'Business hours'], ['24x7', '24×7']].map(([v, l]) => `<button data-cov="${v}" class="${S.coverage === v ? 'on' : ''}" aria-pressed="${S.coverage === v}">${l}</button>`).join('')}</div></label>
  </div>
  <div class="sec"><div class="sec-h"><h2>Per-group certificates</h2><span>${S.conf}% confidence across all three groups (Bonferroni, δ = ${(1 - S.conf / 100) / 3 < 0.01 ? ((1 - S.conf / 100) / 3).toFixed(4) : ((1 - S.conf / 100) / 3).toFixed(3)} each)</span></div>
    <table class="gt"><thead><tr><th>Group</th><th>Legitimate findings</th><th>Certified threshold</th><th>Guarantee</th><th>Takeovers above</th><th>Replay: contained</th><th>Status</th></tr></thead><tbody>${groupsHtml}</tbody></table></div>
  <div class="sec grid2">
    <div class="card"><h3>${K.GROUP_LABEL[g]}: wrong-revocation rate by threshold</h3><p class="cap">${cg.certified ? `Lowest threshold whose upper bound stays under 1 in ${fmtInt(S.alphaInv)}: <b>${cg.threshold.toFixed(3)}</b>. Tested strictest-first; stops at the first failure.` : `Not enough legitimate history to certify 1 in ${fmtInt(S.alphaInv)}: ${fmtInt(cg.n)} findings, needs ${fmtInt(cg.minN)} even with zero wrong revocations.`}</p>
      ${riskChart(g)}
      <div class="legend"><span><i></i>Observed rate</span><span><i class="d"></i>Upper bound (${S.conf}% joint)</span><span><i class="r d"></i>Your limit</span><span><i class="g"></i>Takeovers caught (right axis)</span></div></div>
    <div class="card"><h3>Auto-pause guard</h3><p class="cap">Evidence that the live rate exceeds your limit, updated as each legitimate finding is resolved. Crossing 20 pauses the group (anytime-valid: a false pause has at most 5% chance however often you look).</p>
      ${guardChart(g, R, noGuard)}
      ${tripped.length ? tripped.map(([k, t]) => `<div class="callout"><svg viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg><div><b>${K.GROUP_LABEL[k]} paused ${dayLabel(t, TENANT_TZ)}, ${hhmm(t, TENANT_TZ)} CT</b> after ${R.decisions.filter(dd => dd.g === k && dd.wrong && dd.t < t && (k !== lisbon.group || dd.w === lisbon.week)).length} wrong revocations${k === lisbon.group ? ` in the first days of the ${esc(lisbon.label)}` : ''}. Without the guard: ${noGuard.metrics.byGroup[k].wrong} in the replay.</div></div>`).join('') : `<div class="callout ok"><div><b>No pauses in the replay.</b> ${S.guard ? 'Live labels stayed consistent with the certificate.' : 'The guard is off.'}</div></div>`}
    </div>
  </div>
  <div class="sec"><div class="sec-h"><h2>Replay on held-out weeks</h2><span>${weekRange(P.testWeeks[0]).split(' –')[0]} to ${weekRange(P.testWeeks[1]).split('– ')[1]} · ${fmtInt(M.legit + M.atos)} findings · analysts on ${S.coverage === '24x7' ? '24×7' : 'business hours'}</span></div>
    <div class="kpis">
      <div class="kpi"><em>Contained automatically</em><b>${M.autoContained}<small> of ${M.atos}</small></b><span>confirmed takeovers in the replay</span></div>
      <div class="kpi"><em>Median time to containment</em><b>${K.fmtDuration(M.medianContainMin)}</b><span>vs ${K.fmtDuration(base.metrics.medianContainMin)} with analyst review only</span></div>
      <div class="kpi"><em>Attacker steps prevented</em><b>${M.preventedTotal}<small> of ${M.stepsTotal}</small></b><span>rules, MFA methods, internal sends (review only: ${base.metrics.preventedTotal})</span></div>
      <div class="kpi"><em>Wrong revocations</em><b>${M.wrong}</b><span>${pct(M.wrong / Math.max(1, M.legit), 2)} of ${fmtInt(M.legit)} legitimate findings</span></div>
    </div>
    <table class="cmp"><thead><tr><th>Policy</th><th>Contained automatically</th><th>Median time to containment</th><th>Steps prevented</th><th>Analyst reviews</th><th>Wrong revocations</th><th>Guarantee</th></tr></thead><tbody>
      ${cmpRow('Review only (today)', base.metrics, 'none needed', false)}
      ${cmpRow('Fixed score ≥ 0.90', fixed.metrics, 'none', false)}
      ${cmpRow(`Calibrated, 1 in ${fmtInt(S.alphaInv)}, no guard`, noGuard.metrics, 'holds until behaviour shifts', false)}
      ${cmpRow(`Calibrated, 1 in ${fmtInt(S.alphaInv)}, guard on`, run('calibrated', true).metrics, 'certified + auto-pause', true)}
    </tbody></table></div>
  <div class="how">
    <div><h4>1 · Certify</h4><p>For each group, Learn-then-Test walks thresholds from strict to loose on 8 weeks of resolved findings and keeps going while an exact binomial test says the wrong-revocation rate is below your limit. The joint error is at most ${100 - S.conf}%.</p></div>
    <div><h4>2 · Act on the running score</h4><p>The score is recomputed as each sign-in, rule or send arrives; Aegis revokes the moment it crosses the threshold. Certifying on each finding's maximum score certifies exactly that trigger.</p></div>
    <div><h4>3 · Guard the assumption</h4><p>The certificate assumes next month looks like the calibration weeks. A likelihood-ratio e-process watches resolved findings and pauses only the affected group when that stops being true.</p></div>
  </div>`;
  // wiring
  const setQ = patch => { const nq = { a: S.alphaInv, c: S.conf, g: S.group, guard: S.guard ? 1 : 0, cov: S.coverage, ...patch }; for (const k in nq) nq[k] = String(nq[k]); setHash('containment', nq, true); renderContainment(nq); modePill(); };
  view.querySelectorAll('[data-a]').forEach(b => b.onclick = () => setQ({ a: b.dataset.a }));
  view.querySelectorAll('[data-c]').forEach(b => b.onclick = () => setQ({ c: b.dataset.c }));
  view.querySelectorAll('[data-cov]').forEach(b => b.onclick = () => setQ({ cov: b.dataset.cov }));
  view.querySelectorAll('tr.g').forEach(tr => { tr.onclick = () => setQ({ g: tr.dataset.g }); tr.onkeydown = e => { if (e.key === 'Enter') setQ({ g: tr.dataset.g }); }; });
  $('#guard').onclick = () => setQ({ guard: S.guard ? 0 : 1 });
  view.querySelectorAll('[data-mode]').forEach(b => b.onclick = () => {
    if (b.dataset.mode === 'live' && S.mode !== 'live') return approveModal();
    S.mode = b.dataset.mode; save(); memo.clear(); toast(S.mode === 'off' ? 'Automated containment turned off.' : 'Shadow mode: Aegis records what it would revoke.'); route();
  });
  $('#approve').onclick = () => S.mode === 'live' ? toast('Policy is live. Change the limit to start a new review.') : approveModal();
  $('#exp-json').onclick = () => exportJSON();
  $('#exp-csv').onclick = () => exportCSV(R.decisions, 'aegis-containment-replay.csv');
  wireTips();
}
function cmpRow(name, m, guar, me) {
  return `<tr class="${me ? 'mine' : ''}"><td>${name}</td><td class="num">${m.autoContained} of ${m.atos}</td><td class="num">${K.fmtDuration(m.medianContainMin)}</td><td class="num">${m.preventedTotal} of ${m.stepsTotal}</td><td class="num">${m.reviewQueue}</td><td class="num">${m.wrong}</td><td>${guar}</td></tr>`;
}

// risk vs threshold, computed from the calibration findings
function riskChart(g) {
  const pol = policy(), c = pol[g];
  const benign = P.cal.filter(r => r.g === g && !r.f.y).map(r => r.max).sort((a, b) => b - a);
  const atos = P.cal.filter(r => r.g === g && r.f.y).map(r => r.max);
  const n = benign.length, alpha = c.alpha, dg = c.deltaGroup;
  const xs = Array.from({ length: 60 }, (_, i) => 0.02 + i * (0.6 - 0.02) / 59);
  const pts = xs.map(l => { const k = benign.filter(s => s >= l).length; return { l, emp: k / n, ub: K.cpUpper(k, n, dg), tpr: atos.filter(s => s >= l).length / Math.max(1, atos.length), k }; });
  const ymax = Math.max(alpha * 3, 0.006);
  const Wd = 560, H = 230, L = 46, Rr = 44, T = 12, B = 30;
  const X = l => L + (Wd - L - Rr) * (l - 0.02) / (0.6 - 0.02), Y = v => T + (H - T - B) * (1 - Math.min(v, ymax) / ymax), Y2 = v => T + (H - T - B) * (1 - v);
  const line = (k, f) => pts.map((p, i) => (i ? 'L' : 'M') + X(p.l).toFixed(1) + ' ' + f(p[k]).toFixed(1)).join(' ');
  const yt = [0, ymax / 3, 2 * ymax / 3, ymax];
  const xt = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6];
  return `<svg class="chart" viewBox="0 0 ${Wd} ${H}" role="img" aria-label="Wrong-revocation rate against threshold for ${K.GROUP_LABEL[g]}" data-tipchart="risk">
    ${yt.map(v => `<line class="gl" x1="${L}" x2="${Wd - Rr}" y1="${Y(v)}" y2="${Y(v)}"/><text x="${L - 6}" y="${Y(v) + 3}" text-anchor="end">${pct(v, v < 0.01 ? 2 : 1)}</text>`).join('')}
    ${[0, .5, 1].map(v => `<text x="${Wd - Rr + 6}" y="${Y2(v) + 3}">${v * 100}%</text>`).join('')}
    ${xt.map(v => `<text x="${X(v)}" y="${H - 12}" text-anchor="middle">${v.toFixed(1)}</text>`).join('')}
    <text x="${(L + Wd - Rr) / 2}" y="${H}" text-anchor="middle">score threshold</text>
    <path d="${line('tpr', Y2)}" stroke="#9e9ea7" stroke-width="1.5" fill="none"/>
    <line x1="${L}" x2="${Wd - Rr}" y1="${Y(alpha)}" y2="${Y(alpha)}" stroke="#ff6d6d" stroke-width="1.5" stroke-dasharray="5 4"/>
    <path d="${line('ub', Y)}" stroke="#1f1f23" stroke-width="1.5" stroke-dasharray="4 3" fill="none"/>
    <path d="${line('emp', Y)}" stroke="#1f1f23" stroke-width="2" fill="none"/>
    ${c.certified ? `<line x1="${X(c.threshold)}" x2="${X(c.threshold)}" y1="${T}" y2="${H - B}" stroke="#08080a" stroke-width="1"/><rect x="${X(c.threshold) + 4}" y="${T}" width="104" height="18" rx="3" fill="#08080a"/><text x="${X(c.threshold) + 10}" y="${T + 12.5}" style="fill:#f4f4f5;font-weight:600">CERTIFIED ${c.threshold.toFixed(3)}</text>` : ''}
    <rect x="${L}" y="${T}" width="${Wd - L - Rr}" height="${H - T - B}" fill="transparent" data-hover="1"/>
  </svg><script type="application/json" class="tipdata">${JSON.stringify(pts.map(p => [+p.l.toFixed(3), p.k, n, +p.emp.toFixed(5), +p.ub.toFixed(5), +p.tpr.toFixed(3)]))}</script>`;
}
function guardChart(g, R, noGuard) {
  const tr = (S.guard ? R : noGuard).guardTrace[g];
  const Wd = 460, H = 200, L = 36, Rr = 12, T = 12, B = 30;
  const t0 = (P.testWeeks[0] - 1) * 7 * DAY, t1 = P.testWeeks[1] * 7 * DAY;
  const X = t => L + (Wd - L - Rr) * (t - t0) / (t1 - t0);
  const lo = -2, hi = 2.5, Y = e => T + (H - T - B) * (1 - (Math.max(lo, Math.min(hi, Math.log10(e))) - lo) / (hi - lo));
  const ev = W.meta.events[0], es = (ev.week - 1) * 7 * DAY + 1 * DAY, ee = es + 3 * DAY;
  let path = `M${X(t0)} ${Y(1)}`; for (const p of tr) path += ` L${X(p.t).toFixed(1)} ${Y(p.e).toFixed(1)}`;
  const revs = tr.filter(p => p.revoked);
  const pausedAt = S.guard ? R.paused[g] : null;
  return `<svg class="chart" viewBox="0 0 ${Wd} ${H}" role="img" aria-label="Guard evidence over time for ${K.GROUP_LABEL[g]}">
    ${g === ev.group ? `<rect x="${X(es)}" y="${T}" width="${Math.max(3, X(ee) - X(es))}" height="${H - T - B}" fill="#fdf1f1"/><text x="${X(es) - 6}" y="${H - B - 8}" text-anchor="end" fill="#b42318">${esc(ev.label)}</text>` : ''}
    ${[0.01, 0.1, 1, 10, 100].map(v => `<line class="gl" x1="${L}" x2="${Wd - Rr}" y1="${Y(v)}" y2="${Y(v)}"/><text x="${L - 6}" y="${Y(v) + 3}" text-anchor="end">${v}</text>`).join('')}
    <line x1="${L}" x2="${Wd - Rr}" y1="${Y(20)}" y2="${Y(20)}" stroke="#ff6d6d" stroke-dasharray="5 4" stroke-width="1.5"/><text x="${Wd - Rr}" y="${Y(20) - 5}" text-anchor="end" fill="#d93838">pause at 20</text>
    ${Array.from({ length: P.testWeeks[1] - P.testWeeks[0] + 2 }, (_, i) => (P.testWeeks[0] - 1 + i) * 7 * DAY).filter((t, i) => i % 2 === 0).map(t => `<text x="${X(t)}" y="${H - 12}" text-anchor="middle">${weekRange(t / (7 * DAY) + 1).split(' –')[0]}</text>`).join('')}
    <path d="${path}" stroke="#1f1f23" stroke-width="1.6" fill="none"/>
    ${revs.map(p => `<circle cx="${X(p.t)}" cy="${Y(p.e)}" r="3" fill="#ff6d6d"/>`).join('')}
    ${pausedAt !== null ? `<line x1="${X(pausedAt)}" x2="${X(pausedAt)}" y1="${T}" y2="${H - B}" stroke="#08080a"/><text x="${X(pausedAt) + 6}" y="${T + 10}" fill="#08080a" style="font-weight:600">paused ${dayLabel(pausedAt, TENANT_TZ).slice(4)}</text>` : ''}
  </svg><div class="legend"><span><i></i>Evidence (log scale)</span><span><i class="r" style="border-top-style:solid;width:8px;border-radius:4px"></i>Wrong revocation</span></div>`;
}
function wireTips() {
  const svg = view.querySelector('[data-tipchart=risk]'); if (!svg) return;
  const data = JSON.parse(svg.nextElementSibling.textContent);
  let tip = document.querySelector('.tip'); if (!tip) { tip = document.createElement('div'); tip.className = 'tip'; tip.hidden = true; document.body.appendChild(tip); }
  svg.addEventListener('mousemove', e => {
    const b = svg.getBoundingClientRect(), vx = (e.clientX - b.left) / b.width * 560;
    const l = 0.02 + (vx - 46) / (560 - 46 - 44) * 0.58; if (l < 0.02 || l > 0.6) { tip.hidden = true; return; }
    const p = data.reduce((best, d) => Math.abs(d[0] - l) < Math.abs(best[0] - l) ? d : best, data[0]);
    tip.hidden = false; tip.style.left = (e.clientX + 14) + 'px'; tip.style.top = (e.clientY - 10) + 'px';
    tip.innerHTML = `threshold ${p[0].toFixed(3)}<br>${p[1]} of ${fmtInt(p[2])} legitimate above (${pct(p[3], 2)})<br>upper bound ${pct(p[4], 2)}<br>takeovers caught ${pct(p[5], 0)}`;
  });
  svg.addEventListener('mouseleave', () => tip.hidden = true);
}

// ------------------------------------------------------------------ approve modal
function approveModal() {
  const pol = policy();
  const m = $('#modal'); m.hidden = false;
  m.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-labelledby="mt"><h2 id="mt">Go live with automated containment?</h2>
    <p>Aegis will revoke sessions and delete hidden rules on its own when a finding clears its group's threshold. Everything else still comes to your team.</p>
    <ul>${K.GROUPS.map(g => `<li><span>${K.GROUP_LABEL[g]}</span><b>${pol[g].certified ? 'score ≥ ' + pol[g].threshold.toFixed(3) : 'review only'}</b></li>`).join('')}
    <li><span>Wrong revocations</span><b>≤ 1 in ${fmtInt(S.alphaInv)} legitimate findings, ${S.conf}%</b></li>
    <li><span>Auto-pause guard</span><b>${S.guard ? 'on' : 'off'}</b></li></ul>
    <div class="row"><button class="btn" id="m-cancel">Cancel</button><button class="btn dark" id="m-ok">Approve and go live</button></div></div>`;
  const close = () => { m.hidden = true; m.innerHTML = ''; };
  $('#m-cancel').onclick = close; m.onclick = e => { if (e.target === m) close(); };
  $('#m-ok').onclick = () => { S.mode = 'live'; S.approvedAt = new Date().toISOString(); save(); memo.clear(); close(); toast('Automated containment is live.'); route(); };
  $('#m-ok').focus();
}
function shortcutsModal() {
  const m = $('#modal'); m.hidden = false;
  m.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-labelledby="kt"><h2 id="kt">Keyboard shortcuts</h2><div class="keys">
    <kbd>/</kbd><span>Search accounts</span><kbd>j</kbd><span>Next finding</span><kbd>k</kbd><span>Previous finding</span><kbd>Enter</kbd><span>Open finding</span><kbd>Esc</kbd><span>Back to the list</span><kbd>g f</kbd><span>Go to Findings</span><kbd>g c</kbd><span>Go to Containment</span><kbd>[ ]</kbd><span>Previous / next week</span><kbd>?</kbd><span>This help</span></div>
    <div class="row"><button class="btn dark" id="k-ok">Done</button></div></div>`;
  const close = () => { m.hidden = true; m.innerHTML = ''; };
  $('#k-ok').onclick = close; m.onclick = e => { if (e.target === m) close(); }; $('#k-ok').focus();
}

// ------------------------------------------------------------------ other pages
function renderAccounts(q) {
  const query = (q.q || '').toLowerCase();
  const R = run();
  const rows = [...P.acctFindings.entries()].map(([ai, list]) => {
    const a = W.accounts[ai]; const rep = list.filter(r => r.f.w >= 19); const d = rep.map(r => R.byId.get(r.f.id));
    return { a, n: rep.length, likely: rep.filter(r => r.max >= K.LIKELY).length, auto: d.filter(x => x && x.auto).length, last: rep.length ? rep[rep.length - 1] : null };
  }).filter(x => x.n && (!query || x.a.n.toLowerCase().includes(query) || x.a.e.includes(query))).sort((p, q2) => q2.likely - p.likely || q2.n - p.n).slice(0, 200);
  view.innerHTML = `<div class="ph"><div><h1>Accounts</h1><div class="sub">${fmtInt(W.accounts.length)} mailboxes · watched since May 11 · top 200 by findings in the replay</div></div></div>
  <table class="ft"><thead><tr><th>Account</th><th>Group</th><th>Findings</th><th>Likely takeover</th><th>Revoked automatically</th><th>Last finding</th></tr></thead><tbody>
  ${rows.map(x => `<tr class="row" data-id="${x.last.f.id}"><td><div class="acct"><span class="av" style="background:${avColor(x.a.n)}">${initials(x.a.n)}</span><div><b>${esc(x.a.n)}</b><small>${esc(x.a.e)} · ${esc(x.a.dept)}</small></div></div></td><td>${K.GROUP_LABEL[x.a.g]}</td><td class="score">${x.n}</td><td class="score">${x.likely}</td><td class="score">${x.auto}</td><td><time class="score">${dayLabel(x.last.f.t, TENANT_TZ)}</time></td></tr>`).join('')}</tbody></table>`;
  view.querySelectorAll('tr.row').forEach(tr => tr.onclick = () => setHash('finding/' + tr.dataset.id));
}
function renderPlaceholder(page) {
  const t = { messages: ['Messages', 'Inbound verdicts live here in the product. This concept only covers account takeover, so the message list is not rebuilt.'], settings: ['Settings', 'Tenant connection, audit-log access and roles. Containment policy lives under Containment.'] }[page] || ['Not found', 'That page does not exist.'];
  view.innerHTML = `<div class="ph"><div><h1>${t[0]}</h1></div></div><div class="placeholder"><b>Not part of this concept demo</b>${t[1]} <p><a class="btn" href="#/containment">Open Containment</a></p></div>`;
}

// ------------------------------------------------------------------ export
function download(name, text, type) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }
function exportCSV(decisions, name) {
  const rows = decisions.map(d => { const r = P.byId.get(d.id); return { finding: d.id, week: d.w, account: r.a.e, group: K.GROUP_LABEL[d.g], score: d.max.toFixed(4), takeover: d.y, auto_revoked: d.auto ? 1 : 0, wrong_revocation: d.wrong ? 1 : 0, minutes_to_auto: d.tAuto === null ? '' : d.tAuto.toFixed(2), minutes_to_analyst: d.tAnalyst === null ? '' : d.tAnalyst.toFixed(1), attacker_steps: d.steps, steps_prevented: d.prevented }; });
  download(name, K.toCSV(rows, Object.keys(rows[0] || { finding: '' })), 'text/csv');
  toast(`Exported ${fmtInt(rows.length)} rows.`);
}
function exportJSON() {
  const pol = policy(), R = run('calibrated', S.guard);
  const out = { tenant: W.meta.tenant, generated: new Date().toISOString(), limit: { wrongRevocationsAtMost: `1 in ${S.alphaInv}`, alpha: 1 / S.alphaInv, confidence: S.conf / 100 }, guard: S.guard, mode: S.mode,
    calibrationWeeks: P.calWeeks, groups: Object.fromEntries(K.GROUPS.map(g => { const c = pol[g]; return [g, { label: K.GROUP_LABEL[g], certified: c.certified, threshold: c.threshold, legitimateFindings: c.n, legitimateAbove: c.k, pValue: c.p, deltaGroup: c.deltaGroup, takeoverRecallCalibration: c.calTpr }]; })),
    replay: { weeks: P.testWeeks, ...R.metrics, paused: R.paused } };
  download('aegis-containment-policy.json', JSON.stringify(out, null, 2), 'application/json'); toast('Exported policy JSON.');
}

// ------------------------------------------------------------------ chrome: search, keys, toast
let toastT;
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), 2600); }
$('#q').addEventListener('input', e => { const r = parseHash(); const page = r.page === 'accounts' ? 'accounts' : 'findings'; setHash(page, { ...(page === r.page ? r.q : {}), q: e.target.value || undefined }, true); route(); $('#q').focus(); });
$('#help-btn').onclick = shortcutsModal;
let gPending = 0;
document.addEventListener('keydown', e => {
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
  if (e.key === 'Escape') { if (!$('#modal').hidden) { $('#modal').hidden = true; $('#modal').innerHTML = ''; return; } if (typing) { document.activeElement.blur(); return; } if (current && current.page === 'finding') history.back(); return; }
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === '/') { e.preventDefault(); $('#q').focus(); return; }
  if (e.key === '?') { shortcutsModal(); return; }
  if (e.key === 'g') { gPending = Date.now(); return; }
  if (Date.now() - gPending < 900) { if (e.key === 'f') setHash('findings'); if (e.key === 'c') setHash('containment'); gPending = 0; return; }
  if (current && current.page === 'findings') {
    if (e.key === 'j') { listCursor = Math.min(listIds.length - 1, listCursor + 1); highlightCursor(); }
    if (e.key === 'k') { listCursor = Math.max(0, listCursor - 1); highlightCursor(); }
    if (e.key === 'Enter' && listIds[listCursor]) setHash('finding/' + listIds[listCursor], { from: current.q.week || 26 });
    const wk = +(current.q.week || 26);
    if (e.key === '[' && wk > 19) setHash('findings', { ...current.q, week: wk - 1 });
    if (e.key === ']' && wk < 26) setHash('findings', { ...current.q, week: wk + 1 });
  }
});

boot();
