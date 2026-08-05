// Boot, routing, theme, keyboard and the verification gate.
//
// The gate is the rule that matters: /api/verify is read before any view is
// mounted, and a ledger that fails verification takes the interface over.
// There is no path through this file that renders a healthy console over a
// log the server reported as broken.

import { api, state, recordVerify, recordVerifyError, ledgerBroken } from '/api.js';
import { views } from '/views.js';
import { el, clear, mono, num, panel, stat, table, td, commandBox, errPanel } from '/ui.js';

const viewHost = document.getElementById('view');
const takeover = document.getElementById('takeover');
const alertbar = document.getElementById('alertbar');
const nav = document.getElementById('nav');

let teardown = null;

// ---------- theme ----------

const THEMES = ['auto', 'dark', 'light'];
const themeBtn = document.getElementById('theme-btn');
const themeVal = document.getElementById('theme-btn-val');

function applyTheme(t) {
  if (t === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
  themeVal.textContent = t;
  try { localStorage.setItem('gantry-theme', t); } catch { /* private mode, the default still works */ }
}

function cycleTheme() {
  const now = themeVal.textContent || 'auto';
  applyTheme(THEMES[(THEMES.indexOf(now) + 1) % THEMES.length]);
}

themeBtn.addEventListener('click', cycleTheme);
let stored = 'auto';
try { stored = localStorage.getItem('gantry-theme') || 'auto'; } catch { /* ignore */ }
applyTheme(THEMES.includes(stored) ? stored : 'auto');

// ---------- routing ----------

function parseRoute() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [pathPart, queryPart] = raw.split('?');
  const segments = pathPart.split('/').filter(Boolean);
  const query = {};
  for (const [k, v] of new URLSearchParams(queryPart || '')) query[k] = v;
  const view = segments[0] && views[segments[0]] ? segments[0] : 'overview';
  return { view, segments, query };
}

function markNav(view) {
  for (const a of nav.querySelectorAll('a')) {
    if (a.dataset.view === view) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
}

async function renderRoute() {
  const route = parseRoute();
  markNav(route.view);
  if (teardown) { try { teardown(); } catch { /* ignore */ } teardown = null; }

  // The gate. Nothing mounts over a ledger the server called broken until the
  // reader dismisses the takeover deliberately.
  if ((ledgerBroken() || state.verifyError) && !state.acknowledged) {
    renderTakeover();
    return;
  }
  takeover.hidden = true;
  document.body.classList.remove('takeover-on');
  renderAlertBar();

  try {
    const out = await views[route.view](viewHost, route);
    if (typeof out === 'function') teardown = out;
  } catch (err) {
    clear(viewHost).append(el('div', { class: 'view' }, panel(`The ${route.view} view could not load`, {}, errPanel(err))));
  }
}

window.addEventListener('hashchange', renderRoute);

// ---------- the verification gate ----------

export async function runVerify() {
  try {
    recordVerify(await api.verify());
  } catch (err) {
    recordVerifyError(err);
  }
  renderAlertBar();
  return state.verify;
}

function renderTakeover() {
  const v = state.verify;
  const err = state.verifyError;
  const faults = (v && v.faults) || [];

  const proceed = el('button', {
    class: 'btn', type: 'button', onclick: () => { state.acknowledged = true; renderRoute(); },
  }, 'Open the console anyway, with the failure banner');

  const again = el('button', {
    class: 'btn btn-quiet', type: 'button', onclick: async () => {
      again.disabled = true;
      again.textContent = 'verifying…';
      await runVerify();
      renderRoute();
    },
  }, 'Verify again');

  clear(takeover).append(el('div', { class: 'takeover-box' },
    err
      ? el('div', {},
        el('h1', {}, 'This ledger could not be verified'),
        el('p', { class: 'takeover-lede' },
          'The console reads /api/verify before it renders anything else, and that read failed. ',
          'Nothing below this line has been checked, so this console will not present the record as sound.'),
        errPanel(err))
      : el('div', {},
        el('h1', {}, 'This ledger failed verification'),
        el('p', { class: 'takeover-lede' },
          'The server verified the log on this request and found ',
          el('strong', {}, `${num(faults.length)} fault${faults.length === 1 ? '' : 's'}`),
          ' across ', num(v.entries), ' entries. Treat every page behind this one as a rendering of a record that does not check out. ',
          'A console that showed you a healthy dashboard here would be the exact failure this product exists to prevent.'),

        el('div', { class: 'grid-3', style: 'margin-bottom:14px' },
          stat('faults', num(faults.length), 'envelopes that failed the check', { huge: true, cls: 'fault-text' }),
          stat('entries', num(v.entries), 'envelopes checked'),
          stat('attestations unverified', num(v.attestations_unverified), 'present but under an unregistered key id',
            { cls: v.attestations_unverified ? 'warn-text' : null }),
        ),

        panel('What failed', { flush: true },
          table(
            [{ label: 'index', num: true, width: '8ch' }, { label: 'event', width: '28ch' }, { label: 'fault' }],
            faults.map((f) => el('tr', { class: 'is-faulted' },
              td(mono(num(f.index)), 'num'),
              td(f.id ? el('a', { class: 'mono', href: `#/ledger/${encodeURIComponent(f.id)}` }, f.id) : mono('—'), 'nowrap'),
              td(el('span', { class: 'fault-text' }, f.fault)),
            )),
            { empty: 'the server reported ok: false with no fault list, which is itself a defect worth reporting', rowsAttr: false },
          )),

        el('div', { style: 'margin-top:14px' },
          el('h3', { style: 'font-size:12px; text-transform:lowercase; letter-spacing:.05em; color:var(--fg-dim)' }, 'check this without the server'),
          commandBox(v.reproduce || 'the API did not return a reproduce command'))),

    el('div', { class: 'takeover-actions' }, again, proceed,
      el('span', { class: 'stat-note' }, 'The banner stays for the rest of the session. It cannot be dismissed.')),
  ));
  takeover.hidden = false;
  alertbar.hidden = true;
  document.body.classList.add('takeover-on');
  clear(viewHost);
}

function renderAlertBar() {
  if (!ledgerBroken() && !state.verifyError) {
    alertbar.hidden = true;
    return;
  }
  const v = state.verify;
  const n = v ? (v.faults || []).length : 0;
  clear(alertbar).append(
    el('strong', {}, state.verifyError ? 'This ledger could not be verified' : 'This ledger failed verification'),
    el('span', {}, state.verifyError
      ? 'The console could not read /api/verify, so nothing on this page has been checked.'
      : `${num(n)} fault${n === 1 ? '' : 's'} across ${num(v.entries)} entries. Rows the verifier named are marked in the tables below.`),
    el('a', { href: '#/verify' }, 'open the verification report'),
  );
  alertbar.hidden = false;
}

// ---------- head chip ----------

async function loadHeadChip() {
  const valNode = document.getElementById('head-chip-val');
  try {
    const head = await api.head();
    state.head = head;
    valNode.textContent = `${head.size} · ${String(head.root_hash).replace(/^sha256:/, '').slice(0, 10)}`;
    document.getElementById('head-chip').title =
      `signed tree head: size ${head.size}, root ${head.root_hash}, key ${head.key_id}, ts ${head.ts}`;
  } catch {
    valNode.textContent = 'unreadable';
    document.getElementById('head-chip').title = 'the console could not read /api/head';
  }
}

// ---------- keyboard ----------

const rowsIn = () => [...viewHost.querySelectorAll('tr[data-row]')];

function selected() {
  return viewHost.querySelector('tr[data-row].is-selected');
}

function select(row) {
  const prev = selected();
  if (prev) prev.classList.remove('is-selected');
  if (!row) return;
  row.classList.add('is-selected');
  row.scrollIntoView({ block: 'nearest' });
}

function move(delta) {
  const rows = rowsIn();
  if (rows.length === 0) return;
  const cur = selected();
  const i = cur ? rows.indexOf(cur) : -1;
  const next = rows[Math.min(rows.length - 1, Math.max(0, i + delta))] || rows[0];
  select(next);
}

document.addEventListener('keydown', (e) => {
  // The target is not always an Element: a key pressed with nothing focused
  // can land on the document, which has no matches().
  const typing = e.target instanceof Element && e.target.matches('input, textarea, select');
  if (e.key === 'Escape') {
    if (typing) { e.target.blur(); return; }
    for (const open of viewHost.querySelectorAll('tr.is-open')) open.click();
    select(null);
    return;
  }
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return;

  switch (e.key) {
    case '/': {
      const f = viewHost.querySelector('[data-filter]');
      if (f) { e.preventDefault(); f.focus(); f.select(); }
      break;
    }
    case 'j': e.preventDefault(); move(1); break;
    case 'k': e.preventDefault(); move(-1); break;
    case 'Enter': {
      const row = selected();
      if (row) { e.preventDefault(); row.click(); }
      break;
    }
    case 't': cycleTheme(); break;
    default: {
      const n = Number(e.key);
      if (n >= 1 && n <= 7) {
        const link = nav.querySelectorAll('a')[n - 1];
        if (link) location.hash = link.getAttribute('href');
      }
    }
  }
});

// ---------- boot ----------

window.gantryConsole = { runVerify, renderRoute };

await runVerify();
loadHeadChip();
// Setting the hash fires hashchange, which renders. Only render directly when
// the hash is already set, so a first paint never happens twice.
if (!location.hash) location.hash = '#/overview';
else await renderRoute();
