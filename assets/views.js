// The six views. Each exports an async render(host, route) and may return a
// teardown function, which the router calls before the next view mounts.

import { api, state, ledgerBroken } from '/api.js';
import { trace } from '/trace.js';
import {
  el, clear, mono, panel, stat, kv, table, td, jsonPretty, commandBox, errPanel, loading,
  shortHash, shortId, tsShort, tsDate, durationMs, num, actorId,
  attMark, attRowClass, subjectSummary, volumeChart,
} from '/ui.js';

const EVENT_PAGE_MAX = 1000;

// ---------- shared row machinery ----------

// A table row that expands in place. The detail is built lazily and torn down
// on collapse, so a thousand-row table holds a thousand rows, not a thousand
// detail panes.
//
// `open` is an optional { set, key }. A table that repaints (the ledger view
// repaints every time the five second poll finds new events) builds new rows
// from scratch, so an expansion held only by the old row dies with it. The
// set outlives the repaint and the new row reopens itself, which is what
// makes reading a payload during a live run possible at all.
function expandableRow(cells, colspan, buildDetail, cls, open) {
  const tr = el('tr', { class: cls || null, 'data-row': '' }, cells);
  let detail = null;
  const collapse = () => {
    if (open) open.set.delete(open.key);
    if (!detail) return;
    detail.remove();
    detail = null;
    tr.classList.remove('is-open');
  };
  const expand = () => {
    if (open) open.set.add(open.key);
    if (detail) return;
    const box = el('div', { class: 'detail-grid' });
    detail = el('tr', { class: 'detail' }, el('td', { colspan }, box));
    tr.after(detail);
    tr.classList.add('is-open');
    const out = buildDetail(box);
    if (out && typeof out.then === 'function') out.catch(() => {});
  };
  tr.addEventListener('click', (e) => {
    if (e.target.closest('a, button, input')) return;
    if (detail) collapse();
    else expand();
  });
  // After the caller has put the row in a table: `after` needs a parent, and
  // a row has none while it is being built.
  if (open && open.set.has(open.key)) queueMicrotask(expand);
  return tr;
}

function section(title, ...body) {
  return el('div', {}, el('h3', {}, title), body);
}

const faultFor = (id) => (state.verify && state.verify.faults || []).find((f) => f.id === id);

function eventDetail(box, ev) {
  const f = faultFor(ev.id);
  if (f) {
    box.append(
      el('div', { class: 'errbox', style: 'grid-column:1/-1' },
        el('h3', {}, 'this event failed verification'),
        el('div', { class: 'mono' }, f.fault),
        el('div', { class: 'fix' }, el('b', {}, 'fix: '), 'do not treat this event as evidence, and run the reproduce command on the Verify view to confirm the same verdict offline')),
    );
  }
  box.append(section('identity', kv([
    ['id', mono(ev.id)],
    ['run', ev.run_id ? el('a', { href: `#/run/${encodeURIComponent(ev.run_id)}`, class: 'mono' }, ev.run_id) : mono('—')],
    ['parent', mono(ev.parent_id || 'null')],
    ['seq', mono(String(ev.seq))],
    ['ts', mono(ev.ts)],
    ['kind', mono(ev.kind)],
    ['actor', mono(actorId(ev.actor))],
    ['schema', mono(`v${ev.v}`)],
  ])));

  const auth = ev.authority || {};
  const diverged = Array.isArray(auth.diverged) ? auth.diverged : [];
  box.append(section('authority', kv([
    ['profile', mono(auth.profile ?? '—')],
    ['policy', mono(shortHash(auth.policy_version))],
    ['instruction', mono(shortHash(auth.instruction_version))],
    ['settings', mono(shortHash(auth.settings_hash))],
    ['permission mode', auth.permission_mode === 'unobserved'
      ? el('span', { class: 'tag tag-dashed', title: 'nothing set CLAUDE_PERMISSION_MODE for this run, so the mode was recorded as unobserved rather than guessed' }, 'unobserved')
      : mono(auth.permission_mode ?? '—')],
    ['diverged', diverged.length
      ? el('span', {}, diverged.map((d) => el('span', { class: 'tag tag-warn', style: 'margin-right:4px' }, d)))
      : el('span', { class: 'dim' }, 'none')],
  ])));

  const posSlot = el('div', { class: 'dim' }, 'reading position…');
  box.append(section('attestation and position', el('div', {},
    el('div', { style: 'margin-bottom:6px' }, attMark(ev)),
    ev.attestation
      ? kv([['alg', mono(ev.attestation.alg ?? '—')], ['key id', mono(ev.attestation.key_id ?? '—')], ['value', mono(shortHash(ev.attestation.value, 24))]])
      : el('div', { class: 'dim' }, 'no attestation on this event'),
    el('div', { style: 'margin-top:8px' }, posSlot),
  )));

  box.append(section('hashes', kv([
    ['subject', mono(ev.subject_hash ?? '—')],
    ['prev', mono(ev.prev_hash ?? 'null')],
    ['redacted', (ev.redacted && ev.redacted.length)
      ? el('span', {}, ev.redacted.map((p) => el('span', { class: 'tag', style: 'margin-right:4px' }, p)))
      : el('span', { class: 'dim' }, 'none')],
  ])));

  box.append(el('div', { style: 'grid-column:1/-1' }, section('subject', jsonPretty(ev._subject ?? null))));

  return api.event(ev.id).then(
    (r) => {
      clear(posSlot).append(kv([
        ['position', mono(`${num(r.index)} of ${num(r.tree_size)}`)],
        ['tree size', mono(num(r.tree_size))],
      ]));
    },
    (err) => {
      clear(posSlot).append(el('span', { class: 'dim' }, `position unavailable: ${err.cause_ || err.message}`));
    },
  );
}

// ---------- overview ----------

export async function overview(host) {
  const body = el('div', { class: 'view' }, loading('the scorecard, the head and the event stream'));
  clear(host).append(body);

  const [score, head, evs] = await Promise.all([api.score(), api.head(), api.events({ limit: EVENT_PAGE_MAX })]);
  state.head = head;

  const events = evs.events || [];
  const counts = { verified: 0, absent: 0, unverified: 0, forged: 0 };
  const kinds = new Map();
  for (const e of events) {
    const s = e._attestation_state;
    if (s in counts) counts[s] += 1; else counts.unverified += 1;
    kinds.set(e.kind, (kinds.get(e.kind) || 0) + 1);
  }
  const attested = counts.verified;
  // The read is limit and offset over the ledger in append order, so a
  // truncated page is the oldest events and not the newest. Saying "most
  // recent" here described the page nobody was looking at.
  const sample = evs.total > events.length
    ? `over the first ${num(events.length)} of ${num(evs.total)} events in append order`
    : `over all ${num(evs.total)} events`;

  const overall = score.overall;
  const scored = (score.scores || []).filter((s) => s.score !== null && s.score !== undefined).length;

  clear(body).append(
    el('div', { class: 'grid-3' },
      stat('overall level',
        overall === null || overall === undefined ? el('span', { class: 'prim-na' }, 'N/A') : String(overall),
        overall === null || overall === undefined
          ? 'every layer is N/A: this ledger exercised nothing'
          : `the minimum across ${scored} scored primitives, never the average`,
        { huge: true }),
      stat('events scored', num(score.events_scored), `rules ${score.rules_version}`),
      stat('ledger size', num(head.size), `head signed by ${head.key_id}`),
      stat('attested', `${num(attested)} / ${num(events.length)}`,
        attested === 0 ? `nothing on this ledger carries a verified attestation, ${sample}` : sample,
        { cls: attested === events.length ? null : 'warn-text' }),
    ),

    panel('The twelve primitives', { sub: `scored from telemetry, never from a profile name · rules ${score.rules_version}`, flush: true },
      table(
        [{ label: '#', num: true, width: '3ch' }, { label: 'primitive', width: '18ch' }, { label: 'score', width: '11ch' }, { label: 'evidence' }, { label: 'sample event', width: '22ch' }],
        (score.scores || []).map((s) => el('tr', {},
          td(mono(String(s.primitive)), 'num'),
          td(s.name),
          td(scoreCell(s.score)),
          td(el('span', { class: 'dim' }, s.evidence)),
          td(s.sample_event
            ? el('a', { class: 'mono', href: `#/ledger/${encodeURIComponent(s.sample_event)}` }, shortId(s.sample_event, 18))
            : el('span', { class: 'faint' }, '—')),
        )),
        { empty: 'the scorer returned no primitives', rowsAttr: false },
      )),

    el('div', { class: 'grid-2' },
      panel('Event volume', { sub: `${num(events.length)} events, ${sample.replace('over ', '')}` },
        volumeChart(events),
        el('div', { style: 'margin-top:10px' },
          table(
            [{ label: 'kind' }, { label: 'events', num: true, width: '8ch' }],
            [...kinds.entries()].sort((a, b) => b[1] - a[1]).map(([k, c]) => el('tr', {},
              td(el('a', { class: 'mono', href: `#/ledger?kind=${encodeURIComponent(k)}` }, k)),
              td(mono(num(c)), 'num'),
            )),
            { empty: 'no events', rowsAttr: false },
          ))),

      el('div', { style: 'display:grid; gap:var(--gutter); align-content:start' },
        panel('Attestation coverage', { sub: sample },
          table(
            [{ label: 'state' }, { label: 'events', num: true, width: '8ch' }, { label: 'meaning' }],
            [
              ['verified', counts.verified, 'signature checked against a key in config/actor-keys.json and good'],
              ['unverified', counts.unverified, 'an attestation is present but no registered key matches its key id'],
              ['forged', counts.forged, 'an attestation under a registered key id that fails the check'],
              ['absent', counts.absent, 'no attestation on the event'],
            ].map(([k, c, meaning]) => el('tr', { class: c > 0 && k !== 'verified' ? `att-row-${k}` : null },
              td(attMark({ _attestation_state: k })),
              td(mono(num(c)), 'num'),
              td(el('span', { class: 'dim' }, meaning)),
            )),
            { rowsAttr: false },
          )),

        panel('Signed tree head', { sub: 'the position every inclusion proof is checked against' },
          kv([
            ['size', mono(num(head.size))],
            ['root hash', mono(head.root_hash)],
            ['ts', mono(head.ts)],
            ['key id', mono(head.key_id)],
            ['sig', mono(shortHash(head.sig, 32))],
          ]),
          el('div', { class: 'stat-note', style: 'margin-top:8px' },
            'The console does not check this signature. ',
            el('a', { href: '#/verify' }, 'Verify'),
            ' reports what the server found and prints the offline command that checks the server.')),
      )),
  );
}

function scoreCell(v) {
  if (v === null || v === undefined) {
    return el('span', { class: 'prim-na', title: 'the layer was never exercised on this ledger, which is not the same as a zero' }, 'N/A');
  }
  const bars = el('span', { class: 'prim-score', title: `level ${v} of 5` });
  for (let i = 1; i <= 5; i += 1) bars.append(el('i', { class: i <= v ? 'on' : null }));
  return el('span', {}, mono(String(v)), ' ', bars);
}

// ---------- ledger ----------

const ledgerState = {
  kinds: new Set(),
  run: '',
  actor: '',
  since: '',
  limit: 200,
  offset: 0,
  filter: '',
  live: true,
};

export async function ledger(host, route) {
  // A deep link from a sample event or a fault opens that row once. It must
  // not reopen on every repaint, or typing in the filter would toggle it.
  let pendingFocus = route.segments[1] ? decodeURIComponent(route.segments[1]) : null;
  if (route.query.kind) {
    ledgerState.kinds = new Set([route.query.kind]);
    ledgerState.offset = 0;
  }
  if (route.query.run) {
    ledgerState.run = route.query.run;
    ledgerState.offset = 0;
  }

  const filterInput = el('input', {
    type: 'search',
    'data-filter': '',
    placeholder: 'filter loaded rows by id, kind, actor, run or subject text  ( / )',
    value: ledgerState.filter,
    oninput: (e) => { ledgerState.filter = e.target.value; paint(); },
  });
  const runInput = el('input', { type: 'text', size: 18, placeholder: 'run id', value: ledgerState.run, onchange: (e) => { ledgerState.run = e.target.value.trim(); ledgerState.offset = 0; reload(); } });
  const actorInput = el('input', { type: 'text', size: 14, placeholder: 'actor', value: ledgerState.actor, onchange: (e) => { ledgerState.actor = e.target.value.trim(); ledgerState.offset = 0; reload(); } });
  const sinceInput = el('input', { type: 'text', size: 20, placeholder: 'since (ISO 8601)', value: ledgerState.since, onchange: (e) => { ledgerState.since = e.target.value.trim(); ledgerState.offset = 0; reload(); } });
  const limitSelect = el('select', { onchange: (e) => { ledgerState.limit = Number(e.target.value); ledgerState.offset = 0; reload(); } },
    [50, 100, 200, 500, 1000].map((n) => el('option', { value: String(n), selected: n === ledgerState.limit }, `${n} rows`)));

  const kindChips = el('div', { class: 'chipset' });
  const filters = el('div', { class: 'filters' }, filterInput, runInput, actorInput, sinceInput, limitSelect, kindChips);

  const liveDot = el('span', { class: 'live-dot' });
  const liveBtn = el('button', { class: 'btn btn-quiet', type: 'button', onclick: () => { ledgerState.live = !ledgerState.live; syncLive(); } }, 'live');
  const pageInfo = el('span', { class: 'sub mono' }, '');
  const prevBtn = el('button', { class: 'btn btn-quiet', type: 'button', onclick: () => { ledgerState.offset = Math.max(0, ledgerState.offset - ledgerState.limit); reload(); } }, '← older page');
  const nextBtn = el('button', { class: 'btn btn-quiet', type: 'button', onclick: () => { ledgerState.offset += ledgerState.limit; reload(); } }, 'newer page →');

  const tableSlot = el('div', { class: 'panel-body flush', style: 'display:flex; min-height:0' }, loading('the event stream'));
  const pane = el('section', { class: 'panel' },
    el('div', { class: 'panel-head' },
      el('h2', {}, 'Ledger'),
      el('span', { class: 'sub' }, 'append order, newest last'),
      pageInfo,
      el('span', { class: 'spacer' }),
      liveDot, liveBtn, prevBtn, nextBtn),
    tableSlot);

  clear(host).append(el('div', { class: 'view view-fill' }, filters, pane));

  let rows = [];
  let total = 0;
  let seenIds = new Set();
  let timer = null;
  // Which rows the reader has open, by event id. Survives a repaint, so the
  // poll arriving mid-read no longer closes the payload being read.
  const openRows = new Set();

  function syncLive() {
    const canLive = ledgerState.offset === 0;
    const on = ledgerState.live && canLive;
    liveDot.classList.toggle('on', on);
    liveBtn.textContent = on ? 'live' : 'paused';
    liveBtn.title = canLive
      ? 'poll the API every 5 seconds and animate arriving events'
      : 'polling is off while a page other than the newest is shown';
    if (timer) { clearInterval(timer); timer = null; }
    if (on) timer = setInterval(() => { load(true).catch(() => {}); }, 5000);
  }

  function paintKindChips(all) {
    clear(kindChips);
    for (const k of all) {
      kindChips.append(el('button', {
        class: 'kindchip',
        type: 'button',
        'aria-pressed': ledgerState.kinds.has(k) ? 'true' : 'false',
        onclick: () => {
          if (ledgerState.kinds.has(k)) ledgerState.kinds.delete(k);
          else ledgerState.kinds.add(k);
          ledgerState.offset = 0;
          reload();
        },
      }, k));
    }
  }

  function paint() {
    const q = ledgerState.filter.toLowerCase();
    const shown = q
      ? rows.filter((ev) => JSON.stringify(ev).toLowerCase().includes(q))
      : rows;
    const near = nearBottom(tableSlot.querySelector('.tablewrap'));
    clear(tableSlot).append(table(
      [
        { label: 'attestation', width: '13ch' },
        { label: 'seq', num: true, width: '6ch' },
        { label: 'time', width: '13ch' },
        { label: 'kind', width: '17ch' },
        { label: 'actor', width: '20ch' },
        { label: 'run', width: '16ch' },
        { label: 'subject' },
      ],
      shown.map((ev) => {
        const classes = [attRowClass(ev)];
        if (state.faultIds.has(ev.id)) classes.push('is-faulted');
        if (seenIds.size && !seenIds.has(ev.id)) classes.push('is-new');
        if (pendingFocus && ev.id === pendingFocus) classes.push('is-selected');
        return expandableRow([
          td(attMark(ev)),
          td(mono(String(ev.seq)), 'num'),
          td(el('span', { class: 'mono', title: ev.ts }, tsShort(ev.ts)), 'nowrap'),
          td(mono(ev.kind)),
          td(el('span', { class: 'mono trunc', title: actorId(ev.actor) }, actorId(ev.actor)), 'trunc'),
          td(ev.run_id ? el('a', { class: 'mono', href: `#/run/${encodeURIComponent(ev.run_id)}`, title: ev.run_id }, shortId(ev.run_id, 14)) : mono('—'), 'nowrap'),
          td(subjectSummary(ev), 'trunc'),
        ], 7, (box) => eventDetail(box, ev), classes.join(' '), { set: openRows, key: ev.id });
      }),
      { empty: rows.length ? 'no loaded row matches the filter' : 'no events match these query parameters' },
    ));
    pageInfo.textContent = `${shown.length} shown · ${rows.length} loaded · ${num(total)} match on the ledger · offset ${ledgerState.offset}`;
    const wrap = tableSlot.querySelector('.tablewrap');
    if (wrap && near) wrap.scrollTop = wrap.scrollHeight;
    if (pendingFocus) {
      const sel = tableSlot.querySelector('tr.is-selected');
      if (sel) { sel.scrollIntoView({ block: 'center' }); sel.click(); }
      pendingFocus = null;
    }
  }

  function nearBottom(wrap) {
    if (!wrap) return true;
    return wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 40;
  }

  async function load(isPoll) {
    const params = {
      run: ledgerState.run || undefined,
      actor: ledgerState.actor || undefined,
      since: ledgerState.since || undefined,
      limit: ledgerState.limit,
      offset: ledgerState.offset || undefined,
    };
    if (ledgerState.kinds.size) params.kind = [...ledgerState.kinds];
    const res = await api.events(params);
    const next = res.events || [];
    if (isPoll && next.length === rows.length && next.every((e, i) => rows[i] && rows[i].id === e.id)) return;
    const prev = new Set(rows.map((e) => e.id));
    rows = next;
    seenIds = isPoll ? prev : new Set(next.map((e) => e.id));
    total = res.total ?? next.length;
    paintKindChips(allKinds(rows));
    paint();
    prevBtn.disabled = ledgerState.offset === 0;
  }

  function allKinds(evs) {
    const s = new Set(ledgerState.kinds);
    for (const e of evs) s.add(e.kind);
    return [...s].sort();
  }

  async function reload() {
    try {
      await load(false);
    } catch (err) {
      clear(tableSlot).append(el('div', { style: 'padding:10px; width:100%' }, errPanel(err)));
    }
    syncLive();
  }

  await reload();
  return () => { if (timer) clearInterval(timer); };
}

// ---------- run ----------

export async function run(host, route) {
  const id = route.segments[1] ? decodeURIComponent(route.segments[1]) : null;
  return id ? runDetail(host, id) : runList(host);
}

async function runList(host) {
  const body = el('div', { class: 'view' }, loading('runs'));
  clear(host).append(body);
  const res = await api.runs();
  const runs = res.runs || [];

  clear(body).append(
    el('div', { class: 'grid-3' },
      stat('runs', num(runs.length), 'derived from run.open and run.seal'),
      stat('unsealed', num(runs.filter((r) => !r.sealed).length),
        'a run that opened and never sealed is a crashed or in-flight run',
        { cls: runs.some((r) => !r.sealed) ? 'warn-text' : null }),
      stat('denials', num(runs.reduce((a, r) => a + (r.denials || 0), 0)), 'policy.decision events with a deny verdict'),
    ),
    panel('Runs', { sub: 'newest first · open one for the waterfall', flush: true },
      table(
        [
          { label: 'run id', width: '24ch' }, { label: 'opened', width: '20ch' }, { label: 'sealed after', width: '14ch' },
          { label: 'workload' }, { label: 'events', num: true, width: '8ch' }, { label: 'denials', num: true, width: '9ch' },
          { label: 'unattested', num: true, width: '11ch' }, { label: 'kinds' },
        ],
        runs.map((r) => el('tr', { 'data-row': '', onclick: () => { location.hash = `#/run/${encodeURIComponent(r.run_id)}`; } },
          td(el('a', { class: 'mono', href: `#/run/${encodeURIComponent(r.run_id)}` }, r.run_id), 'nowrap'),
          td(el('span', { class: 'mono', title: r.opened_at }, `${tsDate(r.opened_at)} ${tsShort(r.opened_at)}`), 'nowrap'),
          td(r.sealed
            ? el('span', { class: 'mono', title: r.sealed_at }, durationMs(r.opened_at, r.sealed_at))
            : el('span', { class: 'tag tag-warn', title: 'this run opened and never sealed' }, 'unsealed'), 'nowrap'),
          td(mono(r.workload ?? '—')),
          td(mono(num(r.events)), 'num'),
          td(r.denials ? el('span', { class: 'tag tag-deny' }, num(r.denials)) : el('span', { class: 'faint mono' }, '0'), 'num'),
          td(r.unattested ? el('span', { class: 'warn-text mono' }, num(r.unattested)) : el('span', { class: 'faint mono' }, '0'), 'num'),
          td(el('span', { class: 'mono dim trunc' }, Object.entries(r.kinds || {}).map(([k, c]) => `${k}:${c}`).join('  ')), 'trunc'),
        )),
        { empty: 'no run.open events on this ledger' },
      )),
  );
}

async function runDetail(host, id) {
  const body = el('div', { class: 'view' }, loading(`run ${id}`));
  clear(host).append(body);

  const [runsRes, evsRes, policyRes] = await Promise.all([
    api.runs(),
    api.events({ run: id, limit: EVENT_PAGE_MAX }),
    api.policy().catch(() => null),
  ]);
  const meta = (runsRes.runs || []).find((r) => r.run_id === id);
  const events = evsRes.events || [];
  const ruleMessage = new Map(((policyRes && policyRes.rules) || []).map((r) => [r.id, r.message]));

  // /api/events returns at most EVENT_PAGE_MAX rows and reports how many
  // matched. A waterfall that stopped at a thousand and said nothing would be
  // a complete-looking rendering of an incomplete read, which on this product
  // is a worse failure than refusing to draw the page at all.
  const matched = evsRes.total;
  const truncated = Number(matched) > events.length;
  const dropped = truncated ? matched - events.length : 0;
  const pageNote = truncated
    ? el('div', { class: 'warnbox' },
      el('h3', {}, `this waterfall is the first ${num(events.length)} events of ${num(matched)} on this run`),
      el('div', {}, `${num(dropped)} events carrying this run id are not drawn here. `,
        'The API returns at most ', mono(num(EVENT_PAGE_MAX)), ' events per read, in append order, so what follows is the start of the run and not all of it.'),
      el('div', { class: 'fix' }, el('b', {}, 'fix: '),
        'read the rest in the ',
        el('a', { href: `#/ledger?run=${encodeURIComponent(id)}` }, 'ledger view filtered to this run'),
        ', which pages the same events, or narrow the read with the since filter there.'))
    : null;

  const t0 = events.length ? new Date(events[0].ts).getTime() : 0;
  const tEnd = events.length ? new Date(events[events.length - 1].ts).getTime() : 0;
  const span = Math.max(tEnd - t0, 1);

  clear(body).append(
    el('div', { class: 'filters' },
      el('a', { href: '#/run' }, '← all runs'),
      el('span', { class: 'mono' }, id),
      meta && !meta.sealed ? el('span', { class: 'tag tag-warn' }, 'unsealed') : null,
    ),
    el('div', { class: 'grid-3' },
      stat('events', `${num(events.length)} of ${num(matched)}`,
        truncated
          ? `drawn of the events matching this run id; ${num(dropped)} are not on this page`
          : 'drawn of the events matching this run id, so this waterfall is the whole run',
        { cls: truncated ? 'warn-text' : null }),
      stat('denials', num(meta ? meta.denials : events.filter(isDeny).length), 'each names the rule that fired',
        { cls: (meta ? meta.denials : 0) ? 'deny-text' : null }),
      stat('unattested', num(meta ? meta.unattested : events.filter((e) => e._attestation_state !== 'verified').length),
        'events with no verified attestation', { cls: (meta && meta.unattested) ? 'warn-text' : null }),
      stat('elapsed', meta && meta.sealed ? durationMs(meta.opened_at, meta.sealed_at) : (events.length ? durationMs(events[0].ts, events[events.length - 1].ts) : '—'),
        meta && meta.sealed ? `sealed ${meta.sealed_at}` : 'no run.seal event, so this is first to last event',
        { cls: meta && !meta.sealed ? 'warn-text' : null }),
    ),
    panel('Waterfall', { sub: 'model calls, tool requests, policy decisions, sandbox executions and sensor verdicts in append order', flush: true },
      pageNote,
      table(
        [
          { label: 'attestation', width: '13ch' }, { label: 'seq', num: true, width: '6ch' },
          { label: 'offset', num: true, width: '9ch' }, { label: 'when', width: '20ch' },
          { label: 'kind', width: '17ch' }, { label: 'detail' },
        ],
        events.map((ev) => {
          const at = new Date(ev.ts).getTime();
          const pct = Number.isNaN(at) ? 0 : ((at - t0) / span) * 100;
          const deny = isDeny(ev);
          const bar = el('div', { class: 'wf-bar' }, el('i', { class: deny ? 'deny' : null, style: `left:${Math.min(99, Math.max(0, pct))}%` }));
          const rule = ev._subject && ev._subject.rule;
          const detail = el('div', {},
            subjectSummary(ev),
            deny ? el('span', { class: 'wf-note' }, ruleMessage.get(rule) || `denied by ${rule || 'a rule the policy route does not name'}`) : null,
          );
          const classes = [attRowClass(ev)];
          if (state.faultIds.has(ev.id)) classes.push('is-faulted');
          return expandableRow([
            td(attMark(ev)),
            td(mono(String(ev.seq)), 'num'),
            td(mono(Number.isNaN(at) ? '—' : `+${((at - t0) / 1000).toFixed(3)}s`), 'num'),
            td(el('div', { style: 'display:flex; align-items:center; gap:6px' }, el('span', { class: 'mono', title: ev.ts }, tsShort(ev.ts)), bar), 'nowrap'),
            td(mono(ev.kind)),
            td(detail),
          ], 6, (box) => eventDetail(box, ev), classes.join(' '));
        }),
        { empty: 'no events carry this run id' },
      )),
  );
}

const isDeny = (ev) => ev.kind === 'policy.decision' && ev._subject && (ev._subject.decision === 'deny' || ev._subject.verdict === 'deny');

// ---------- policy ----------

export async function policy(host) {
  const body = el('div', { class: 'view' }, loading('the loaded policy'));
  clear(host).append(body);
  const p = await api.policy();
  const rules = p.rules || [];
  const caps = p.capabilities || [];
  const never = rules.filter((r) => !r.fired).length;

  clear(body).append(
    el('div', { class: 'grid-3' },
      stat('profile', p.profile ?? '—', 'the loaded policy, not a profile name the scorer trusts'),
      stat('rules', num(rules.length), `${num(never)} never fired`),
      stat('capabilities', num(caps.length), 'each declares a rung, an effect and a rollback where the gate needs one'),
      stat('version', shortHash(p.version, 14), 'sha256 over the loaded policy'),
    ),
    panel('Rules', { sub: 'a rule with zero firings is shown, not hidden: it is either dead weight or a control that has never been tested', flush: true },
      table(
        [{ label: 'rule id', width: '26ch' }, { label: 'decision', width: '10ch' }, { label: 'fired', num: true, width: '8ch' }, { label: 'message' }],
        rules.map((r) => el('tr', {},
          td(mono(r.id), 'nowrap'),
          td(r.decision === 'deny'
            ? el('span', { class: 'tag tag-deny' }, 'deny')
            : el('span', { class: 'tag' }, r.decision ?? '—')),
          td(r.fired ? mono(num(r.fired)) : el('span', { class: 'tag tag-dashed', title: 'this rule has never fired on this ledger' }, 'never'), 'num'),
          td(el('span', { class: 'dim' }, r.message ?? '—')),
        )),
        { empty: 'the policy declares no rules', rowsAttr: false },
      )),
    panel('Capabilities', { sub: 'declared here, gated on the rung replayed from the ledger', flush: true },
      table(
        [{ label: 'capability', width: '22ch' }, { label: 'declared rung', width: '14ch' }, { label: 'effect', width: '16ch' }, { label: 'rollback' }],
        caps.map((c) => el('tr', {},
          td(el('a', { class: 'mono', href: '#/trust' }, c.id), 'nowrap'),
          td(mono(c.rung ?? '—')),
          td(mono(c.effect ?? '—')),
          td(c.rollback ? mono(c.rollback) : el('span', { class: 'faint' }, 'none declared')),
        )),
        { empty: 'the policy declares no capabilities', rowsAttr: false },
      )),
  );
}

// ---------- trust ----------

export async function trust(host) {
  const body = el('div', { class: 'view' }, loading('replayed rungs'));
  clear(host).append(body);
  const t = await api.trust();
  const caps = t.capabilities || [];
  const differ = caps.filter((c) => c.declared_rung !== c.earned_rung);

  clear(body).append(
    el('div', { class: 'grid-3' },
      stat('capabilities', num(caps.length), 'each rung replayed from capability.run and rung.change'),
      stat('earned differs from declared', num(differ.length),
        differ.length ? 'the broker gates on the earned rung' : 'every capability sits at its declared rung',
        { cls: differ.length ? 'warn-text' : null }),
      stat('rung changes', num(caps.reduce((a, c) => a + ((c.history || []).length), 0)), 'promotions and demotions on the record'),
    ),
    panel('Trust budget', { sub: 'declared comes from the policy, earned comes from replay, and the broker gates on earned · open a row for its history', flush: true },
      table(
        [
          { label: 'capability', width: '22ch' }, { label: 'declared', width: '13ch' }, { label: 'earned', width: '24ch' },
          { label: 'clean runs at rung', num: true, width: '18ch' }, { label: 'changes', num: true, width: '9ch' }, { label: 'latest' },
        ],
        caps.map((c) => {
          const diff = c.declared_rung !== c.earned_rung;
          const hist = c.history || [];
          const last = hist[hist.length - 1];
          return expandableRow([
            td(mono(c.capability), 'nowrap'),
            td(el('span', { class: 'rung dim' }, c.declared_rung ?? '—')),
            td(diff
              ? el('span', { class: 'rung rung-differs', title: 'the earned rung differs from the declared one, and the broker gates on this value' }, `${c.earned_rung ?? '—'} (gated on)`)
              : el('span', { class: 'rung' }, c.earned_rung ?? '—'), 'nowrap'),
            td(mono(num(c.clean_since_rung)), 'num'),
            td(mono(num(hist.length)), 'num'),
            td(last
              ? el('span', { class: 'mono dim' }, `${last.from ?? '?'} → ${last.to ?? '?'}  ${last.approver || 'no approver'}`)
              : el('span', { class: 'faint' }, 'no rung change on the record')),
          ], 6, (box) => {
            box.append(el('div', { style: 'grid-column:1/-1' },
              section('history, replayed from the ledger',
                table(
                  [{ label: 'ts', width: '22ch' }, { label: 'event', width: '22ch' }, { label: 'kind', width: '14ch' }, { label: 'from', width: '12ch' }, { label: 'to', width: '12ch' }, { label: 'approver' }],
                  hist.map((h) => el('tr', {},
                    td(mono(h.ts ?? '—'), 'nowrap'),
                    td(h.event_id ? el('a', { class: 'mono', href: `#/ledger/${encodeURIComponent(h.event_id)}` }, shortId(h.event_id, 18)) : mono('—')),
                    td(mono(h.kind ?? '—')),
                    td(mono(h.from ?? '—')),
                    td(mono(h.to ?? '—')),
                    td(h.approver ? mono(h.approver) : el('span', { class: 'faint' }, 'none')),
                  )),
                  { empty: 'no rung.change events for this capability', rowsAttr: false },
                ))));
          });
        }),
        { empty: 'no capability has been exercised on this ledger' },
      )),
  );
}

// ---------- inbox ----------
//
// Every call the policy held, and what the record says has happened to it.
// The console prints the command; it never runs one. A button here would
// write an approval carrying a human's name with nothing behind it but a
// loopback port, and that is a different claim from the one the approval
// path makes.

const HOLD_STATE = {
  waiting: {
    label: 'waiting',
    cls: 'tag tag-warn',
    note: 'nobody has answered this call on the record',
  },
  refused: {
    label: 'refused',
    cls: 'tag tag-deny',
    note: 'a human recorded a deny, and the call stays held; a refusal releases nothing',
  },
  spent: {
    label: 'grant spent',
    cls: 'tag tag-dashed',
    note: 'a grant released this call once and was spent, and it has been held again since; a grant is single use, so this needs a new approval',
  },
  ineffective: {
    label: 'approver not permitted',
    cls: 'tag tag-deny',
    note: 'an approve grant is on the ledger under an approver this policy trust budget does not permit, so the broker will not release the call',
  },
  released: {
    label: 'released',
    cls: 'tag',
    note: 'a usable grant is on the ledger; the next identical call runs and spends it',
  },
};

const holdState = (h) => HOLD_STATE[h.state] || {
  label: `unknown state ${h.state}`,
  cls: 'tag tag-warn',
  note: 'the API returned a state this console does not know; read /api/approvals directly',
};

function grantTable(h) {
  return table(
    [
      { label: 'ts', width: '24ch' }, { label: 'verdict', width: '10ch' }, { label: 'approver', width: '24ch' },
      { label: 'grant', width: '24ch' }, { label: 'spent', width: '10ch' }, { label: 'permitted' },
    ],
    (h.grants || []).map((g) => el('tr', {},
      td(mono(g.ts || '?'), 'nowrap'),
      td(g.verdict === 'deny'
        ? el('span', { class: 'tag tag-deny' }, 'deny')
        : el('span', { class: 'tag' }, g.verdict || '?')),
      td(mono(g.approver || 'unnamed')),
      td(g.event_id
        ? el('a', { class: 'mono', href: `#/ledger/${encodeURIComponent(g.event_id)}` }, shortId(g.grant_id || g.event_id, 18))
        : mono(g.grant_id || '?')),
      td(g.spent
        ? el('span', { class: 'tag tag-dashed', title: `spent by an approval.use at ${g.spent_at}` }, 'spent')
        : el('span', { class: 'faint' }, 'no')),
      td(g.permitted
        ? el('span', { class: 'dim' }, 'yes, under this policy trust budget')
        : el('span', { class: 'deny-text' }, 'no, and the broker re-checks this where the grant is used')),
    )),
    { empty: 'nobody has answered this call: there is no approval event naming it', rowsAttr: false },
  );
}

function holdDetail(box, h, approvers) {
  box.append(section('the call', kv([
    ['tool', mono(h.tool || '?')],
    ['target', mono(h.target || '?')],
    ['capability', mono(h.capability ?? 'none named')],
    ['rule', mono(h.rule)],
    ['call hash', mono(h.call_hash)],
    ['held', mono(`${num(h.held)} time${h.held === 1 ? '' : 's'}`)],
    ['first held', mono(h.first_held_at)],
    ['last held', mono(h.last_held_at)],
  ])));

  box.append(section('what the record says', el('div', {},
    el('div', { class: 'stat-note', style: 'margin-bottom:8px' }, holdState(h).note),
    el('div', {},
      el('a', { href: `#/ledger/${encodeURIComponent(h.decision_event)}`, class: 'mono' }, 'open the policy.decision'),
      ' · ',
      el('a', { href: `#/run/${encodeURIComponent(h.run_id)}`, class: 'mono' }, 'open the run')),
  )));

  box.append(el('div', { style: 'grid-column:1/-1' }, section('approvals on the record', grantTable(h))));

  box.append(el('div', { style: 'grid-column:1/-1' }, section(
    h.releases_next_call ? 'this call is already released' : 'resolve it from a terminal',
    h.releases_next_call
      ? el('p', { class: 'stat-note' },
        'A usable grant is on the ledger. Make the same call again and the broker spends it: the policy.decision still reads hold, because that is what the policy computed, and the release is a separate approval.use.')
      : el('div', {},
        commandBox(h.approve_command),
        el('p', { class: 'stat-note', style: 'margin:8px 0 0' },
          'Run it from the harness root: gantry approve reads config/policy.json from the working directory. ',
          approvers === 'any'
            ? 'This profile permits any approver, so replace the placeholder with your own identity; approving your own call is permitted here and recorded as self_approved on the approval.use.'
            : 'This profile names its approvers, and a grant from anyone else releases nothing.',
          ' Add deny as a last argument to record a refusal instead, which is an event and not an absent one.'),
        el('p', { class: 'stat-note', style: 'margin:6px 0 0' },
          'The console never writes an approval. It reports what is waiting and prints the command a named human runs.')),
  )));
}

export async function inbox(host, route) {
  const body = el('div', { class: 'view' }, loading('held calls'));
  clear(host).append(body);
  // #/inbox/<call hash> opens that hold. A held call is the thing one person
  // hands another, so it gets a link, and the same registry that keeps a row
  // open across a repaint is what opens it.
  const focus = route && route.segments[1] ? decodeURIComponent(route.segments[1]) : null;
  const openHolds = new Set(focus ? [focus] : []);
  const a = await api.approvals();
  const holds = a.holds || [];
  const approvers = a.approvers;
  const blocked = holds.filter((h) => !h.releases_next_call);
  const released = holds.filter((h) => h.releases_next_call);
  const unanswered = blocked.filter((h) => h.state === 'waiting').length;

  const row = (h) => {
    const s = holdState(h);
    const last = (h.grants || [])[(h.grants || []).length - 1];
    return expandableRow([
      td(el('span', { class: s.cls, title: s.note }, s.label), 'nowrap'),
      td(el('span', { class: 'mono', title: h.last_held_at }, `${tsDate(h.last_held_at)} ${tsShort(h.last_held_at)}`), 'nowrap'),
      td(mono(h.rule), 'nowrap'),
      td(mono(h.capability ?? 'none named'), 'nowrap'),
      td(el('span', { class: 'mono trunc', title: `${h.tool} ${h.target}` }, `${h.tool} ${h.target}`), 'trunc'),
      td(mono(num(h.held)), 'num'),
      td(last
        ? el('span', { class: 'mono dim' }, `${last.verdict} by ${last.approver} at ${tsShort(last.ts)}`)
        : el('span', { class: 'faint' }, 'nobody has looked')),
    ], 7, (box) => holdDetail(box, h, approvers), focus === h.call_hash ? 'is-selected' : null,
    { set: openHolds, key: h.call_hash });
  };

  clear(body).append(
    el('div', { class: 'grid-3' },
      stat('held and not released', num(blocked.length),
        blocked.length ? 'each is a run waiting on a human' : 'nothing on this ledger is waiting on a human',
        { huge: true, cls: blocked.length ? 'warn-text' : null }),
      stat('nobody has looked', num(unanswered), 'held calls with no approval event naming them',
        { cls: unanswered ? 'warn-text' : null }),
      stat('released, not yet retried', num(released.length), 'a usable grant sits on the ledger for these'),
      stat('permitted approvers', approvers === 'any' ? 'any' : num((approvers || []).length),
        approvers === 'any'
          ? 'trust_budget.promotion.approver is any on this profile, so self approval is permitted and recorded'
          : (approvers || []).join(', ')),
    ),

    panel('Waiting for a human', {
      sub: 'a hold is not a failure, it is a call waiting for an answer · open a row for the command that resolves it',
      flush: true,
    }, table(
      [
        { label: 'state', width: '22ch' }, { label: 'last held', width: '22ch' }, { label: 'rule', width: '16ch' },
        { label: 'capability', width: '16ch' }, { label: 'call' }, { label: 'held', num: true, width: '6ch' },
        { label: 'latest answer', width: '38ch' },
      ],
      blocked.map(row),
      { empty: 'no held call on this ledger is waiting: every hold has a usable grant, or nothing was ever held' },
    )),

    panel('Released, waiting for the retry', {
      sub: 'an approval is single use and bound to the call hash, so the retry spends it and the next call is held again',
      flush: true,
    }, table(
      [
        { label: 'state', width: '22ch' }, { label: 'last held', width: '22ch' }, { label: 'rule', width: '16ch' },
        { label: 'capability', width: '16ch' }, { label: 'call' }, { label: 'held', num: true, width: '6ch' },
        { label: 'latest answer', width: '38ch' },
      ],
      released.map(row),
      { empty: 'no grant on this ledger releases a call right now' },
    )),

    panel('Why there is no approve button here', {}, el('p', { class: 'stat-note', style: 'margin:0' },
      'The API is GET only and this view writes nothing. An approval names the human who gave it, and a click on a loopback port names nobody: ',
      'the console has no identity story, so a button here would put a name on the ledger that the record could not stand behind. ',
      'The command above runs at a terminal, under whoever is at it, and the ledger records the answer either way.')),
  );
}

// ---------- verify ----------

export async function verify(host) {
  const body = el('div', { class: 'view' });
  clear(host).append(body);
  paint();

  function paint() {
    const v = state.verify;
    const err = state.verifyError;
    clear(body);

    const rerun = el('button', { class: 'btn', type: 'button', onclick: async () => {
      rerun.disabled = true;
      rerun.textContent = 'verifying…';
      try {
        await window.gantryConsole.runVerify();
      } finally {
        rerun.disabled = false;
        rerun.textContent = 'run verification again';
      }
      // A ledger that just went broken takes the interface over again, unless
      // the reader already dismissed a takeover this session.
      if ((ledgerBroken() || state.verifyError) && !state.acknowledged) window.gantryConsole.renderRoute();
      else paint();
    } }, 'run verification again');

    if (err) {
      body.append(
        panel('Verification state unknown', { sub: 'the console could not read /api/verify' },
          errPanel(err),
          el('p', {}, 'Until this route answers, nothing on this console should be read as a verified record. ',
            'The console reports what the server found, and right now it found nothing.'),
          rerun),
      );
      return;
    }
    if (!v) {
      body.append(panel('Verification', {}, loading('the verification result'), rerun));
      return;
    }

    const faults = v.faults || [];
    const blocks = [
      el('div', { class: 'grid-3' },
        stat('result', v.ok ? 'ok' : 'FAILED',
          v.ok ? 'the server found no fault on this ledger' : `${num(faults.length)} fault${faults.length === 1 ? '' : 's'} on the record`,
          { huge: true, cls: v.ok ? null : 'fault-text' }),
        stat('entries', num(v.entries), 'envelopes checked'),
        stat('attestations verified', num(v.attestations_verified), 'checked against a key in config/actor-keys.json'),
        stat('attestations unverified', num(v.attestations_unverified),
          'present but under a key id no registered key matches, counted and never passed',
          { cls: v.attestations_unverified ? 'warn-text' : null }),
      ),

      faults.length
        ? panel('Faults', { sub: 'each names the envelope that failed and what failed about it', flush: true },
          table(
            [{ label: 'index', num: true, width: '8ch' }, { label: 'event', width: '26ch' }, { label: 'fault' }],
            faults.map((f) => el('tr', { class: 'is-faulted' },
              td(mono(num(f.index)), 'num'),
              td(f.id ? el('a', { class: 'mono', href: `#/ledger/${encodeURIComponent(f.id)}` }, f.id) : mono('—'), 'nowrap'),
              td(el('span', { class: 'fault-text' }, f.fault)),
            )),
            { rowsAttr: false },
          ))
        : null,

      panel('Reproduce this offline', { sub: 'the console never presents its own verification as independent' },
        commandBox(v.reproduce || 'the API did not return a reproduce command'),
        el('p', { class: 'stat-note', style: 'margin:8px 0 0' },
          'Run that command against the same ledger directory and you reach this verdict without the server. ',
          'This page reports what the server found and hands you the command that checks the server.'),
        el('div', { style: 'margin-top:10px' }, rerun)),

      v.head
        ? panel('Signed head at verification', {}, kv([
          ['size', mono(num(v.head.size))],
          ['root hash', mono(v.head.root_hash)],
          ['ts', mono(v.head.ts)],
          ['key id', mono(v.head.key_id)],
          ['sig', mono(v.head.sig)],
        ]))
        : null,
    ];
    body.append(...blocks.filter(Boolean));
  }
}

export const views = { overview, ledger, run, trace, policy, trust, inbox, verify };
