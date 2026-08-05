// Rendering helpers shared by the six views. DOM built as nodes, never as
// concatenated HTML, so no value from the ledger is ever parsed as markup.

export function el(tag, props, ...children) {
  const node = document.createElement(tag);
  if (props && (props.nodeType || Array.isArray(props) || typeof props === 'string')) {
    children.unshift(props);
    props = null;
  }
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = String(v);
    // No innerHTML escape hatch on purpose: every value here comes from the
    // ledger and must never be parsed as markup.
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  add(node, children);
  return node;
}

function add(node, kids) {
  for (const k of kids) {
    if (k === null || k === undefined || k === false) continue;
    if (Array.isArray(k)) add(node, k);
    else node.append(k.nodeType ? k : document.createTextNode(String(k)));
  }
}

export const clear = (n) => {
  while (n.firstChild) n.removeChild(n.firstChild);
  return n;
};

export const mono = (s, cls) => el('span', { class: cls ? `mono ${cls}` : 'mono' }, s ?? '');

// ---------- formatting ----------

// Hashes stay recognisable at both ends: the prefix names the algorithm and
// the tail is what changes when a byte changes.
export function shortHash(h, keep = 10) {
  if (!h) return '—';
  const s = String(h);
  const i = s.indexOf(':');
  const algo = i > 0 ? s.slice(0, i + 1) : '';
  const body = i > 0 ? s.slice(i + 1) : s;
  if (body.length <= keep + 6) return s;
  return `${algo}${body.slice(0, keep)}…${body.slice(-4)}`;
}

export function shortId(id, keep = 12) {
  if (!id) return '—';
  const s = String(id);
  return s.length <= keep + 2 ? s : `${s.slice(0, keep)}…`;
}

export function tsShort(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

export function tsDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

export function durationMs(a, b) {
  const t0 = new Date(a).getTime();
  const t1 = new Date(b).getTime();
  if (Number.isNaN(t0) || Number.isNaN(t1)) return '—';
  const ms = t1 - t0;
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
  return `${Math.floor(ms / 60000)}m${String(Math.round((ms % 60000) / 1000)).padStart(2, '0')}s`;
}

export const num = (n) => (n === null || n === undefined ? '—' : Number(n).toLocaleString('en-US'));

export function actorId(actor) {
  if (!actor) return '—';
  if (typeof actor === 'string') return actor;
  return actor.id || actor.kind || actor.type || JSON.stringify(actor);
}

// ---------- attestation state ----------
//
// Four states, four glyphs. Shape first so the distinction survives a
// monochrome screen or a reader who cannot separate the two warm colours;
// colour second. A verified row gets no colour, which is why a clean board
// cannot be manufactured by styling.

const ATT = {
  verified: { glyph: '·', label: 'verified', title: 'signature checked against a registered key and good' },
  absent: { glyph: '○', label: 'unattested', title: 'no attestation on this event' },
  unverified: { glyph: '?', label: 'unverified', title: 'an attestation is present but no registered key matches its key id' },
  forged: { glyph: '!', label: 'forged', title: 'an attestation under a registered key id that fails the check' },
};

export function attState(ev) {
  const s = ev && ev._attestation_state;
  return ATT[s] ? s : 'unverified';
}

export function attMark(ev) {
  const s = attState(ev);
  const d = ATT[s];
  const raw = ev && ev._attestation_state;
  return el(
    'span',
    { class: `att att-${s}`, title: raw === s ? d.title : `unknown attestation state ${JSON.stringify(raw)}, treated as unverified` },
    el('span', { class: 'att-glyph' }, d.glyph),
    d.label,
  );
}

export const attRowClass = (ev) => `att-row-${attState(ev)}`;

// ---------- structure ----------

export function panel(title, opts = {}, ...body) {
  const head = el(
    'div',
    { class: 'panel-head' },
    el('h2', {}, title),
    opts.sub ? el('span', { class: 'sub' }, opts.sub) : null,
    opts.right ? el('span', { class: 'spacer' }) : null,
    opts.right || null,
  );
  const bodyNode = el('div', { class: opts.flush ? 'panel-body flush' : 'panel-body' }, body);
  return el('section', { class: 'panel' }, head, bodyNode);
}

export function stat(key, value, note, opts = {}) {
  return el(
    'div',
    { class: 'stat' },
    el('div', { class: 'stat-k' }, key),
    el('div', { class: `stat-v${opts.huge ? ' huge' : ''}${opts.cls ? ` ${opts.cls}` : ''}` }, value),
    note ? el('div', { class: 'stat-note' }, note) : null,
  );
}

export function kv(pairs) {
  const dl = el('dl', { class: 'kv' });
  for (const [k, v] of pairs) {
    if (v === undefined) continue;
    dl.append(el('dt', {}, k), el('dd', {}, v));
  }
  return dl;
}

// A table that scrolls inside its own box, so the page body never scrolls
// sideways no matter how wide a hash column gets.
export function table(cols, rows, opts = {}) {
  const thead = el(
    'thead',
    {},
    el('tr', {}, cols.map((c) => el('th', { class: c.num ? 'num' : null, style: c.width ? `width:${c.width}` : null }, c.label))),
  );
  const tbody = el('tbody', {}, rows);
  const t = el('table', {}, thead, tbody);
  const wrap = el('div', { class: 'tablewrap' }, t);
  if (opts.rowsAttr !== false) wrap.setAttribute('data-rows', '');
  if (rows.length === 0) {
    return el('div', { class: 'tablewrap' }, t, el('div', { class: 'empty' }, opts.empty || 'nothing here'));
  }
  return wrap;
}

export const td = (v, cls) => el('td', { class: cls || null }, v);

// ---------- json ----------

export function jsonPretty(value) {
  const pre = el('pre', { class: 'json' });
  pre.append(...highlight(value, 0));
  return pre;
}

function highlight(v, depth) {
  const pad = (n) => '  '.repeat(n);
  const span = (cls, s) => el('span', { class: cls }, s);
  if (v === null) return [span('b', 'null')];
  if (typeof v === 'number') return [span('n', String(v))];
  if (typeof v === 'boolean') return [span('b', String(v))];
  if (typeof v === 'string') return [span('s', JSON.stringify(v))];
  if (Array.isArray(v)) {
    if (v.length === 0) return ['[]'];
    const out = ['[\n'];
    v.forEach((x, i) => {
      out.push(pad(depth + 1), ...highlight(x, depth + 1), i < v.length - 1 ? ',\n' : '\n');
    });
    out.push(pad(depth), ']');
    return out;
  }
  const keys = Object.keys(v);
  if (keys.length === 0) return ['{}'];
  const out = ['{\n'];
  keys.forEach((k, i) => {
    out.push(pad(depth + 1), span('k', JSON.stringify(k)), ': ', ...highlight(v[k], depth + 1), i < keys.length - 1 ? ',\n' : '\n');
  });
  out.push(pad(depth), '}');
  return out;
}

// ---------- misc ----------

export function commandBox(cmd) {
  const code = el('code', {}, cmd);
  const btn = el('button', {
    type: 'button',
    onclick: async () => {
      try {
        await navigator.clipboard.writeText(cmd);
        btn.textContent = 'copied';
      } catch {
        btn.textContent = 'select it manually';
      }
      setTimeout(() => { btn.textContent = 'copy'; }, 1600);
    },
  }, 'copy');
  return el('div', { class: 'cmd' }, code, btn);
}

export function errPanel(err) {
  return el(
    'div',
    { class: 'errbox' },
    el('h3', {}, err.status ? `${err.path} failed with HTTP ${err.status}` : 'the console could not read the API'),
    el('div', { class: 'mono' }, err.cause_ || err.message),
    err.fix ? el('div', { class: 'fix' }, el('b', {}, 'fix: '), err.fix) : null,
  );
}

export function loading(what) {
  return el('div', { class: 'empty' }, `reading ${what}…`);
}

// Bar chart of event volume over time. Inline SVG, no library, no dependency.
export function volumeChart(events, buckets = 60) {
  const times = events.map((e) => new Date(e.ts).getTime()).filter((t) => !Number.isNaN(t));
  if (times.length === 0) return el('div', { class: 'empty' }, 'no timestamped events to chart');
  const lo = Math.min(...times);
  const hi = Math.max(...times);
  const span = Math.max(hi - lo, 1);
  const counts = new Array(buckets).fill(0);
  for (const t of times) counts[Math.min(buckets - 1, Math.floor(((t - lo) / span) * buckets))] += 1;
  const peak = Math.max(...counts);
  const w = 100 / buckets;
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'spark');
  svg.setAttribute('viewBox', '0 0 100 40');
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `${events.length} events between ${new Date(lo).toISOString()} and ${new Date(hi).toISOString()}`);
  counts.forEach((c, i) => {
    if (c === 0) return;
    const h = Math.max(1, (c / peak) * 38);
    const r = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    r.setAttribute('x', String(i * w + w * 0.12));
    r.setAttribute('y', String(40 - h));
    r.setAttribute('width', String(w * 0.76));
    r.setAttribute('height', String(h));
    if (c === peak) r.setAttribute('class', 'hot');
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `${c} event${c === 1 ? '' : 's'}`;
    r.append(title);
    svg.append(r);
  });
  return el(
    'div',
    {},
    svg,
    el(
      'div',
      { class: 'spark-axis' },
      el('span', {}, new Date(lo).toISOString().replace('T', ' ').slice(0, 19)),
      el('span', {}, `peak ${peak}/bucket`),
      el('span', {}, new Date(hi).toISOString().replace('T', ' ').slice(0, 19)),
    ),
  );
}

// One-line summary of a subject, per kind. Falls back to the first scalar
// fields so an unknown kind still says something true rather than nothing.
export function subjectSummary(ev) {
  const s = ev && ev._subject;
  if (!s || typeof s !== 'object') return el('span', { class: 'faint' }, ev && ev.subject_hash ? 'payload expired or withheld, hash retained' : '—');
  const parts = [];
  const push = (label, value, cls) => {
    if (value === undefined || value === null || value === '') return;
    parts.push(el('span', { class: cls || null }, label ? `${label} ` : '', mono(String(value))));
  };
  switch (ev.kind) {
    case 'policy.decision': {
      const d = s.decision || s.verdict;
      const deny = d === 'deny';
      parts.push(el('span', { class: deny ? 'tag tag-deny' : 'tag' }, String(d ?? '?')));
      push('', s.rule);
      push('tool', s.tool);
      break;
    }
    case 'tool.request':
      push('', s.tool || s.tool_id);
      push('sandbox', s.sandbox || s.sandbox_kind);
      break;
    case 'tool.result':
      push('', s.outcome, s.outcome && s.outcome !== 'ok' ? 'deny-text' : null);
      push('for', s.request_id && shortId(s.request_id, 10));
      break;
    case 'model.call':
      push('', s.model || s.provider);
      push('tok', s.tokens_total ?? s.tokens ?? undefined);
      break;
    case 'sensor.verdict':
      push('', s.sensor || s.sensor_id);
      push('', s.verdict ?? (s.pass === true ? 'pass' : s.pass === false ? 'fail' : undefined), s.pass === false || s.verdict === 'fail' || s.verdict === 'broken' ? 'deny-text' : null);
      break;
    case 'capability.run':
      push('', s.capability);
      push('rung', s.rung);
      push('', s.outcome, s.outcome && s.outcome !== 'clean' ? 'deny-text' : null);
      break;
    case 'rung.change':
      push('', s.capability);
      push('', `${s.from ?? '?'} → ${s.to ?? '?'}`);
      push('by', s.trigger);
      break;
    case 'run.open':
      push('', s.workload || s.workload_id);
      push('profile', s.profile);
      break;
    case 'run.seal':
      push('', s.outcome, s.outcome && s.outcome !== 'ok' ? 'deny-text' : null);
      push('events', s.events ?? s.event_count);
      break;
    case 'approval':
      push('', s.verdict, s.verdict === 'deny' ? 'deny-text' : null);
      push('by', s.approver);
      break;
    case 'skill.resolve':
      push('', s.skill || s.skill_id);
      push('', s.verdict, s.verdict === 'rejected' ? 'deny-text' : null);
      push('sig', s.signature || s.signature_state);
      break;
    case 'score.snapshot':
      push('overall', s.overall);
      push('rules', s.rules_version);
      break;
    default:
      for (const [k, v] of Object.entries(s)) {
        if (parts.length >= 3) break;
        if (v === null || typeof v === 'object') continue;
        push(k, String(v).slice(0, 48));
      }
  }
  if (parts.length === 0) return el('span', { class: 'faint' }, 'subject present, no summary fields');
  const wrap = el('span', { class: 'trunc' });
  parts.forEach((p, i) => {
    if (i) wrap.append(document.createTextNode('  '));
    wrap.append(p);
  });
  return wrap;
}
