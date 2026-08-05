# Wiring the console into the binary

Six text files, no build step, no binary asset. The logo is a data URI inside
`console.css`, so `include_str!` covers everything and nothing needs
`include_bytes!`.

Paths below are relative to `src/console.rs`.

## The asset table

```rust
/// The console's static assets, embedded at build time. Text only: the logo
/// travels as a data URI inside the stylesheet, so there is no binary asset
/// and no second process serving files.
const ASSETS: &[(&str, &str, &str)] = &[
    ("/",             include_str!("../assets/index.html"), "text/html; charset=utf-8"),
    ("/index.html",   include_str!("../assets/index.html"), "text/html; charset=utf-8"),
    ("/console.css",  include_str!("../assets/console.css"), "text/css; charset=utf-8"),
    ("/app.js",       include_str!("../assets/app.js"),   "text/javascript; charset=utf-8"),
    ("/api.js",       include_str!("../assets/api.js"),   "text/javascript; charset=utf-8"),
    ("/ui.js",        include_str!("../assets/ui.js"),    "text/javascript; charset=utf-8"),
    ("/views.js",     include_str!("../assets/views.js"), "text/javascript; charset=utf-8"),
];

/// Body and content type for a static path. `None` means the caller should
/// serve the shell, because the front end owns its own routing.
fn asset(path: &str) -> Option<(&'static str, &'static str)> {
    ASSETS.iter().find(|(p, _, _)| *p == path).map(|(_, body, ct)| (*body, *ct))
}

/// The shell, served for every non-API path that is not one of the assets
/// above. Matches the rule in docs/CONSOLE-API.md.
fn shell() -> (&'static str, &'static str) {
    (include_str!("../assets/index.html"), "text/html; charset=utf-8")
}
```

## Request routing

In the order the console needs:

1. `path` starts with `/api/` — the API router owns it. An unknown `/api/*`
   path is 404 with a `Fault` body, never the shell. A shell served under a
   JSON content type would make `fetch` fail with a parse error instead of a
   readable fault.
2. `asset(path)` returns `Some` — serve that body and content type.
3. anything else — serve `shell()` with 200.

The three ES modules are requested by absolute path (`/app.js` imports
`/api.js`, `/ui.js` and `/views.js`), so those exact paths must resolve. A
module served under a content type that is not a JavaScript MIME type is
refused by the browser and the console renders as a blank shell, so the
`text/javascript` above is load-bearing, not cosmetic.

`index.html` references `/console.css` and `/app.js` only. Everything else is
reached through module imports.

## Headers

- `content-length` on every response, as the existing scorecard handler
  already does.
- `cache-control: no-store` on `/api/*`, because every response is derived
  from the ledger on the request and a cached page is a page that may be wrong.
- `cache-control: no-cache` on the assets is enough. They change only when the
  binary changes, and no-cache still lets a revalidation return 304 if the
  handler ever grows an ETag.

## What the console assumes

- Same origin for everything. There is no absolute URL anywhere in `assets/`:
  no font, no script, no image, no `fetch` to any host. Grep for `http` in
  `assets/` returns only the SVG namespace and the inline data URI.
- The API answers exactly the shapes in `docs/CONSOLE-API.md`. Where the
  contract is silent the front end degrades and says so on screen rather than
  guessing (for example an unreadable `/api/events/:id` renders as "position
  unavailable", never as a fabricated index).
- `/api/verify` is read before any view mounts. A body with `ok: false`, and a
  read that fails outright, both take the interface over.

## Not embedded

`dev/` is developer tooling: a fixture server and two fixture sets. Nothing in
`src/` may reference it, and no `include_str!` points at it.
