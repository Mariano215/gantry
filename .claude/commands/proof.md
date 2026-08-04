---
description: Write the proof document that closes a slice
---

A slice is not done because the feature works. It is done when an adversarial
case has been run and recorded.

Produce `docs/proof/NN.md` for slice $ARGUMENTS with these sections, and do
not write any section from reasoning — run the thing and paste what happened.

## 1. The claim
One sentence. What this slice asserts is now true of the system.

## 2. The attack
The case that should fail. Not "here is the feature working" — the hostile
input, the tampered record, the killed process, the removed permission.
Include the exact command or fixture.

## 3. What happened
Verbatim output. The denial, the verifier's complaint, the blocked gate, the
resumed run. If the ledger recorded it, include the event ids and the
inclusion proof.

## 4. What surprised you
Anything that failed for a reason nobody predicted. This section is the
steering loop and it is the most valuable part of the document. If it is
empty, say so explicitly rather than deleting the heading.

## 5. Conformance delta
Which primitives moved, from what to what, and the new overall level — which
is the minimum across applicable primitives, never the average. State N/A
where the workload does not exercise a layer.

## 6. What is still a guide
Anything this slice added as documentation with nothing enforcing it. Mark it
`[UNENFORCED]` in `CLAUDE.md` too.
