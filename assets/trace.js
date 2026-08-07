// The trace view: the ledger as swimlanes on a clock.
//
// A lane is an actor that wrote an event. Nothing else is a lane, and no lane
// is invented. An arrow needs two ends and an event records one, so this file
// holds no table mapping an event kind to a source and a destination: an edge
// is drawn only where a producer recorded a peer, and everything else is a
// marker on a single lane. The picture starts sparse, and that sparseness is
// the finding. It names the handoffs this system does not observe.

import { api, state } from '/api.js';
import {
  el, svgEl, clear, mono, panel, loading, actorId, attMark, attRowClass,
  subjectSummary, num, tsShort, table, td,
} from '/ui.js';
// views.js imports this module, so this is a cycle. It is safe because the
// binding is read when a pane is built and never while either module is
// evaluating, and it beats a second copy of the detail tree that would drift
// from the one the ledger view shows.
import { eventDetail } from '/views.js';

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

  // A hold and the approval that answered it, linked by the call hash both
  // record. Before the decision carried its own call hash this pair was only
  // reachable by position, which is why it is drawn now and was not before.
  // A refusal ends the wait too, so it makes a span; the verdict rides along
  // because a span that read the same for yes and no would erase the
  // distinction the approval path exists to draw.
  const spans = [];
  const heldAt = new Map();
  for (const m of marks) {
    const s = m.ev._subject || {};
    if (m.ev.kind === 'policy.decision' && s.verdict === 'hold' && s.call_hash) {
      if (!heldAt.has(s.call_hash)) heldAt.set(s.call_hash, m);
    }
    if (m.ev.kind === 'approval' && s.call_hash && heldAt.has(s.call_hash)) {
      const held = heldAt.get(s.call_hash);
      spans.push({
        from: held,
        to: m,
        ms: Math.max(m.at - held.at, 0),
        callHash: s.call_hash,
        rule: s.rule,
        verdict: s.verdict === 'deny' ? 'refused' : 'approved',
        approver: s.approver,
      });
      heldAt.delete(s.call_hash);
    }
  }

  return { lanes: [...lanes.values()], marks, edges, spans, t0, span };
}

export async function trace(host, route) {
  const body = el('div', { class: 'view' }, loading('trace'));
  clear(host).append(body);

  // #/trace/<run id> and #/trace/event/<event id> share segment 1. The literal
  // "event" is the discriminator, and anything else is a run id.
  const isEvent = route.segments[1] === 'event';
  const run = !isEvent && route.segments[1] ? decodeURIComponent(route.segments[1]) : null;
  const focusId = isEvent && route.segments[2] ? decodeURIComponent(route.segments[2]) : null;
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
    el('div', { class: focusId ? 'trace-split' : null },
      panel('Trace', {
        sub: `${num(model.lanes.length)} lanes, ${num(events.length)} of ${num(res.total)} events drawn`,
        flush: true,
      },
      legend(model),
      gapList(gapsOnScreen(model)),
      spanList(model),
      el('div', { class: 'lane-stack' }, edgeLayer(model, laneIndex), laneBoard(model))),
      detailPane(model, focusId)),
    panel('Lanes', {
      sub: 'sorted by denials, because that is the lane worth opening',
      flush: true,
    }, laneStats(model)),
  );
}

function laneStats(model) {
  const rows = model.lanes.map((lane) => {
    const marks = lane.marks;
    const subj = (m) => m.ev._subject || {};
    return {
      lane,
      marks,
      denials: marks.filter((m) => subj(m).verdict === 'deny').length,
      holds: marks.filter((m) => subj(m).verdict === 'hold').length,
      heldMs: model.spans
        .filter((s) => s.from.lane === lane.id)
        .reduce((a, s) => a + s.ms, 0),
      unattested: marks.filter((m) => m.ev._attestation_state !== 'verified').length,
    };
  }).sort((a, b) => b.denials - a.denials || b.marks.length - a.marks.length);

  // A peer lane holds no marks of its own, because nothing on the record was
  // written by it. Its row says so rather than printing a zero, which would
  // describe a lane that ran and did nothing.
  const none = () => el('span', { class: 'faint' }, 'none of its own');
  const zero = () => el('span', { class: 'faint mono' }, '0');

  return table(
    [
      { label: 'lane', width: '26ch' }, { label: 'events', num: true, width: '9ch' },
      { label: 'denials', num: true, width: '9ch' }, { label: 'holds', num: true, width: '8ch' },
      { label: 'held', num: true, width: '9ch' }, { label: 'unattested', num: true, width: '12ch' },
      { label: 'first', num: true, width: '10ch' }, { label: 'last', num: true, width: '10ch' },
    ],
    rows.map((r) => el('tr', {},
      td(mono(r.lane.id), 'nowrap'),
      td(r.marks.length ? mono(num(r.marks.length)) : none(), 'num'),
      td(r.denials ? el('span', { class: 'tag tag-deny' }, num(r.denials)) : zero(), 'num'),
      td(r.holds ? el('span', { class: 'tag tag-warn' }, num(r.holds)) : zero(), 'num'),
      td(r.heldMs ? mono(`${(r.heldMs / 1000).toFixed(1)}s`) : zero(), 'num'),
      td(r.unattested ? el('span', { class: 'warn-text mono' }, num(r.unattested)) : zero(), 'num'),
      td(r.marks.length ? mono(`+${(r.marks[0].offsetMs / 1000).toFixed(2)}s`) : none(), 'num'),
      td(r.marks.length
        ? mono(`+${(r.marks[r.marks.length - 1].offsetMs / 1000).toFixed(2)}s`)
        : none(), 'num'),
    )),
    { empty: 'no events on this filter, so no lane has statistics' },
  );
}

// The holes the verify route already found. That route is read once before any
// view mounts, so this is the last report rather than a second read. A gap
// belongs to a run, so only gaps whose run is on screen are drawn.
function gapsOnScreen(model) {
  const gaps = (state.verify && state.verify.seq_gaps) || [];
  return gaps.filter((g) => model.marks.some((m) => m.ev.run_id === g.run_id));
}

function gapList(gaps) {
  if (!gaps.length) return null;
  return el('div', { class: 'trace-gaps' }, gaps.map((g) =>
    el('div', { class: 'trace-gap' },
      el('b', {}, `${num(g.missing)} events missing`),
      el('span', {}, ` between seq ${num(g.after)} and ${num(g.before)} on `),
      mono(g.run_id),
      // A finding, never a fault. An altered entry breaks the chain and shows
      // up as one, so a hole is an event that was never appended, and the log
      // cannot tell a harness killed mid-run from a producer that numbered an
      // event it failed to write.
      el('span', { class: 'faint' },
        'a hole in the record, not an alteration; an altered entry faults on the chain instead'))));
}

// A hold and the answer to it, with the real wait between them.
function spanList(model) {
  if (!model.spans.length) return null;
  return el('div', { class: 'trace-spans' }, model.spans.map((s) =>
    el('div', { class: 'trace-span' },
      el('b', {}, `held ${(s.ms / 1000).toFixed(1)}s`),
      el('span', { class: s.verdict === 'refused' ? 'deny-text' : null }, s.verdict),
      mono(s.rule || 'no rule on the approval'),
      s.approver ? el('span', { class: 'faint mono' }, s.approver) : null,
      el('a', { class: 'mono faint', href: `#/trace?f=${encodeURIComponent(`call:${s.callHash}`)}` },
        'follow this call'))));
}

// The detail tree the ledger view already builds, docked beside the graph and
// opened from its own route rather than from a click, which is what makes it
// reachable without a browser driver.
function detailPane(model, focusId) {
  if (!focusId) return null;
  const m = model.marks.find((x) => x.ev.id === focusId);
  if (!m) {
    return el('aside', { class: 'trace-aside' },
      el('div', { class: 'trace-aside-head' }, mono(focusId)),
      el('p', { class: 'faint' },
        'this event is not on the page the trace drew, so there is nothing to open. It may sit outside the current filter, or beyond the events this read returned.'));
  }
  const box = el('div', { class: 'trace-detail' });
  eventDetail(box, m.ev);
  return el('aside', { class: 'trace-aside' },
    el('div', { class: 'trace-aside-head' },
      mono(m.ev.id),
      el('span', { class: 'faint mono' },
        `+${(m.offsetMs / 1000).toFixed(3)}s from first, +${(m.deltaMs / 1000).toFixed(3)}s from previous`),
      el('a', { href: '#/trace' }, 'close')),
    box);
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
    whereEachTermRan(filter),
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

// Where each term ran, and how it matched. The same syntax means two things
// depending on which side answered it: kind and run are exact at the API, so
// kind:tool draws nothing while rule:r- matches four events on a prefix. A
// filter language that silently changes its matching rule is one people learn
// to distrust, so the bar says which rule applied to which term rather than
// leaving the reader to infer it from an empty page.
function whereEachTermRan(filter) {
  const parts = [];
  const server = Object.keys(filter.server);
  if (server.length) {
    const exact = server.filter((f) => f !== 'actor' && f !== 'since');
    const loose = server.filter((f) => f === 'actor');
    if (exact.length) parts.push(`${exact.join(', ')} on the server, whole value`);
    if (loose.length) parts.push(`${loose.join(', ')} on the server, substring`);
    if (server.includes('since')) parts.push('since on the server, at or after');
  }
  const client = filter.client.map((t) => t.field);
  if (client.length) parts.push(`${[...new Set(client)].join(', ')} in the browser, substring`);
  if (filter.words.length) parts.push('bare text in the browser, substring');
  if (!parts.length) return null;
  return el('span', { class: 'faint' }, parts.join('; '));
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
    title: `${m.ev.kind} at ${tsShort(m.ev.ts)}, +${(m.offsetMs / 1000).toFixed(3)}s from first, +${(m.deltaMs / 1000).toFixed(3)}s from previous`,
    // A route rather than a handler that mutates, so the pane is reachable by
    // link and the render gate can open it without a browser driver.
    onclick: () => {
      location.hash = `#/trace/event/${encodeURIComponent(m.ev.id)}`;
    },
  }, attMark(m.ev), mono(m.ev.kind), subjectSummary(m.ev));
}
