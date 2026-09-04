//! Strict security headers applied to every response.
//!
//! CSP forbids inline JS and any cross-origin resource. Pages reference
//! `<script src="/static/js/...js">` only.
//!
//! `headers()` returns the list of `(name, value)` pairs; `main.rs` stacks
//! one `SetResponseHeaderLayer` per pair on the router. Keeping the values
//! here as data (not as a layer-stack type) keeps the type signatures sane.

pub fn headers() -> &'static [(&'static str, &'static str)] {
    &[
        ("content-security-policy", CSP),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("permissions-policy", PERMISSIONS_POLICY),
        ("cross-origin-opener-policy", "same-origin"),
        // Refuse to let any other origin load our responses as a
        // no-cors subresource (`<img>`, `<script>`, etc.). With COOP
        // above, this puts the document in a cross-origin-isolated
        // context and closes the Spectre-class cross-origin read
        // surface. Everything we serve is same-origin, so this never
        // rejects a legitimate request.
        ("cross-origin-resource-policy", "same-origin"),
    ]
}

//  `data:` in img-src is for the inline SVG caret on <select> in
//  app.css. A data: URI is bytes embedded in our own stylesheet — no
//  request leaves the browser, so it can neither track nor exfiltrate.
const CSP: &str = "\
default-src 'self'; \
script-src 'self'; \
style-src 'self'; \
img-src 'self' data:; \
connect-src 'self'; \
font-src 'self'; \
base-uri 'none'; \
form-action 'self'; \
frame-ancestors 'none'; \
object-src 'none'";

const PERMISSIONS_POLICY: &str =
    "geolocation=(), camera=(), microphone=(), interest-cohort=(), browsing-topics=()";
