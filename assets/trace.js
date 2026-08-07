// The trace view: the ledger as swimlanes on a clock.
//
// A lane is an actor that wrote an event. Nothing else is a lane, and no lane
// is invented. An arrow needs two ends and an event records one, so this file
// holds no table mapping an event kind to a source and a destination: an edge
// is drawn only where a producer recorded a peer, and everything else is a
// marker on a single lane. The picture starts sparse, and that sparseness is
// the finding. It names the handoffs this system does not observe.

import { api } from '/api.js';
import {
  el, svgEl, clear, mono, panel, loading, actorId, attMark, attRowClass,
  subjectSummary, num, tsShort,
} from '/ui.js';

export const EVENT_PAGE_MAX = 1000;

// The one place a peer is read. Each entry names the subject field the
// producer actually writes, so a new lane means a producer recorded
// something, never that this list grew an opinion.
const PEER_FIELD = {
  'model.call': (s) => (s.provider ? `provider:${s.provider}` : null),
  'tool.request': (s) => (s.tool ? `tool:${s.tool}` : null),
  'subagent.spawn': (s) => (s.child_id ? `agent:${s.child_id}` : null),
};

function peerOf(ev) {
  const f = PEER_FIELD[ev.kind];
  if (!f) return null;
  return f(ev._subject || {});
}

// Terms the events route can answer. Everything else runs in the browser over
// the page that route returned, which is why the bar reports both numbers.
const SERVER_FIELDS = new Set(['kind', 'run', 'actor', 'since']);
const CLIENT_FIELDS = new Set([
  'lane', 'verdict', 'rule', 'capability', 'tool', 'provider', 'att', 'call', 'request',
]);

export function parseFilter(text) {
  const server = {};
  const client = [];
  const words = [];
  for (const raw of String(text || '').trim().split(/\s+/).filter(Boolean)) {
    const negate = raw.startsWith('!');
    const token = negate ? raw.slice(1) : raw;
    const i = token.indexOf(':');
    const field = i > 0 ? token.slice(0, i) : null;
    const value = i > 0 ? token.slice(i + 1) : token;
    if (field && SERVER_FIELDS.has(field) && !negate) server[field] = value;
    else if (field && (SERVER_FIELDS.has(field) || CLIENT_FIELDS.has(field))) {
      client.push({ field, value, negate });
    } else words.push(value.toLowerCase());
  }
  return { server, client, words };
}

const FIELD_OF = {
  lane: (ev) => actorId(ev.actor),
  actor: (ev) => actorId(ev.actor),
  kind: (ev) => ev.kind,
  run: (ev) => ev.run_id,
  att: (ev) => ev._attestation_state,
  verdict: (ev) => (ev._subject || {}).verdict,
  rule: (ev) => (ev._subject || {}).rule,
  capability: (ev) => (ev._subject || {}).capability,
  tool: (ev) => (ev._subject || {}).tool,
  provider: (ev) => (ev._subject || {}).provider,
  call: (ev) => (ev._subject || {}).call_hash,
  request: (ev) => (ev._subject || {}).request_id,
};

export function matches(ev, filter) {
  for (const t of filter.client) {
    const read = FIELD_OF[t.field];
    const got = String((read ? read(ev) : null) ?? '');
    const hit = got === t.value || got.includes(t.value);
    if (hit === t.negate) return false;
  }
  if (filter.words.length) {
    const hay = JSON.stringify(ev).toLowerCase();
    if (!filter.words.every((w) => hay.includes(w))) return false;
  }
  return true;
}

export function derive(events) {
  const lanes = new Map();
  const laneFor = (id) => {
    if (!lanes.has(id)) lanes.set(id, { id, marks: [] });
    return lanes.get(id);
  };

  const t0 = events.length ? new Date(events[0].ts).getTime() : 0;
  const tEnd = events.length ? new Date(events[events.length - 1].ts).getTime() : 0;
  const span = Math.max(tEnd - t0, 1);

  const marks = [];
  let prevAt = t0;
  for (const ev of events) {
    const laneId = actorId(ev.actor);
    const at = new Date(ev.ts).getTime();
    const mark = {
      ev,
      lane: laneId,
      at: Number.isNaN(at) ? t0 : at,
      offsetMs: Number.isNaN(at) ? 0 : at - t0,
      deltaMs: Number.isNaN(at) ? 0 : at - prevAt,
      peer: peerOf(ev),
    };
    if (!Number.isNaN(at)) prevAt = at;
    laneFor(laneId).marks.push(mark);
    if (mark.peer) laneFor(mark.peer);
    marks.push(mark);
  }

  // An edge exists where a producer recorded a peer, and nowhere else. The
  // return leg of a tool call is a second edge, drawn only because tool.result
  // carries the request_id of the request it answers.
  const edges = [];
  const openByRequest = new Map();
  for (const m of marks) {
    const s = m.ev._subject || {};
    if (m.peer) {
      edges.push({
        from: m.lane,
        to: m.peer,
        at: m.at,
        offsetMs: m.offsetMs,
        ev: m.ev,
        durationMs: typeof s.latency_ms === 'number' ? s.latency_ms : null,
        back: false,
      });
      if (s.request_id) openByRequest.set(s.request_id, m);
    }
    if (m.ev.kind === 'tool.result' && s.request_id && openByRequest.has(s.request_id)) {
      const req = openByRequest.get(s.request_id);
      edges.push({
        from: req.peer,
        to: m.lane,
        at: m.at,
        offsetMs: m.offsetMs,
        ev: m.ev,
        durationMs: typeof s.duration_ms === 'number' ? s.duration_ms : null,
        back: true,
      });
    }
  }

  return { lanes: [...lanes.values()], marks, edges, spans: [], t0, span };
}

export async function trace(host, route) {
  const body = el('div', { class: 'view' }, loading('trace'));
  clear(host).append(body);

  const run = route.segments[1] ? decodeURIComponent(route.segments[1]) : null;
  const expr = route.query.f
    ? decodeURIComponent(route.query.f)
    : (run ? `run:${run}` : '');
  const filter = parseFilter(expr);
  if (run) filter.server.run = run;

  const res = await api.events({ ...filter.server, limit: EVENT_PAGE_MAX });
  const page = res.events || [];
  const events = page.filter((ev) => matches(ev, filter));
  const model = derive(events);
  const laneIndex = new Map(model.lanes.map((l, i) => [l.id, i]));

  clear(body).append(
    filterBar(expr, events.length, page.length, res.total, filter),
    panel('Trace', {
      sub: `${num(model.lanes.length)} lanes, ${num(events.length)} of ${num(res.total)} events drawn`,
      flush: true,
    },
    legend(model),
    el('div', { class: 'lane-stack' }, edgeLayer(model, laneIndex), laneBoard(model))),
  );
}

function filterBar(expr, shown, page, total, filter) {
  const clientRan = filter.client.length > 0 || filter.words.length > 0;
  const truncated = Number(total) > page;
  const terms = filter.client
    .map((t) => t.field)
    .concat(filter.words.length ? ['text'] : []);
  return el('div', { class: 'filters' },
    el('input', {
      class: 'filter-input mono',
      type: 'text',
      value: expr,
      'data-filter': '',
      placeholder: 'kind:policy.decision verdict:deny capability:vcs.publish',
      'aria-label': 'trace filter',
      onchange: (e) => {
        location.hash = `#/trace?f=${encodeURIComponent(e.target.value)}`;
      },
    }),
    el('span', { class: 'mono' }, `${num(shown)} of ${num(page)} drawn`),
    el('span', { class: 'faint' }, `${num(total)} match the server-side part of this filter`),
    // A browser-side filter over a page is a filter over a page. Reporting
    // three results while the log holds more would be a complete-looking
    // rendering of an incomplete read, which is the failure this console
    // refuses everywhere else.
    clientRan && truncated
      ? el('span', { class: 'warn-text' },
        `${terms.join(', ')} ran in the browser over the first ${num(page)} matching events, not over the log. `,
        el('a', { href: `#/trace?f=${encodeURIComponent(narrower(filter))}` },
          'narrow the server-side read'))
      : null);
}

// The same expression with only the terms the API can answer, which is the
// read that makes the count whole.
function narrower(filter) {
  return Object.entries(filter.server).map(([k, v]) => `${k}:${v}`).join(' ');
}

// Edges are drawn in one SVG layer behind the marks, because a line between
// two rows is not a child of either.
function edgeLayer(model, laneIndex) {
  const rowH = 39;
  const height = Math.max(model.lanes.length * rowH, rowH);
  return svgEl('svg', {
    class: 'edges',
    viewBox: `0 0 1000 ${height}`,
    preserveAspectRatio: 'none',
    'aria-hidden': 'true',
  }, model.edges.map((e) => {
    const from = laneIndex.get(e.from);
    const to = laneIndex.get(e.to);
    if (from === undefined || to === undefined) return null;
    const x = Math.min(998, Math.max(2, (e.offsetMs / model.span) * 1000));
    return svgEl('line', {
      x1: x,
      y1: from * rowH + rowH / 2,
      x2: x,
      y2: to * rowH + rowH / 2,
      class: e.back ? 'edge edge-back' : 'edge',
    });
  }));
}

function legend(model) {
  return el('div', { class: 'trace-legend' },
    el('span', { class: 'mono' }, `${num(model.edges.length)} edges observed`),
    // Printed even though it is zero by construction. A diagram people trust
    // has to say what it refused to draw.
    el('span', { class: 'mono faint' }, 'inferred: 0'),
    el('span', { class: 'faint' },
      'an arrow is drawn only where a producer recorded a peer; every other event is a marker on one lane'));
}

function laneBoard(model) {
  return el('div', { class: 'lanes' }, model.lanes.map((lane) =>
    el('div', { class: 'lane', 'data-lane': lane.id },
      el('div', { class: 'lane-head' },
        mono(lane.id),
        el('span', { class: 'faint' }, `${num(lane.marks.length)} events`)),
      el('div', { class: 'lane-track' }, lane.marks.map((m) => markNode(m, model))))));
}

function markNode(m, model) {
  const pct = (m.offsetMs / model.span) * 100;
  return el('button', {
    class: `mark ${attRowClass(m.ev)}`,
    type: 'button',
    'data-kind': m.ev.kind,
    'data-event': m.ev.id,
    style: `left:${Math.min(99.5, Math.max(0, pct))}%`,
    title: `${m.ev.kind} at ${tsShort(m.ev.ts)}`,
  }, attMark(m.ev), mono(m.ev.kind), subjectSummary(m.ev));
}
