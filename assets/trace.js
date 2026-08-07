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
  el, clear, mono, panel, loading, actorId, attMark, attRowClass,
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

  return { lanes: [...lanes.values()], marks, edges: [], spans: [], t0, span };
}

export async function trace(host, route) {
  const body = el('div', { class: 'view' }, loading('trace'));
  clear(host).append(body);

  const run = route.segments[1] ? decodeURIComponent(route.segments[1]) : null;
  const res = await api.events(run
    ? { run, limit: EVENT_PAGE_MAX }
    : { limit: EVENT_PAGE_MAX });
  const events = res.events || [];
  const model = derive(events);

  clear(body).append(
    el('div', { class: 'filters' },
      run ? el('a', { href: '#/trace' }, 'all runs') : null,
      run ? el('span', { class: 'mono' }, run) : null),
    panel('Trace', {
      sub: `${num(model.lanes.length)} lanes, ${num(events.length)} of ${num(res.total)} events drawn`,
      flush: true,
    }, laneBoard(model)),
  );
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
