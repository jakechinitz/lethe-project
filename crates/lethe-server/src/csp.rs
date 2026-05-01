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
    ]
}

const CSP: &str = "\
default-src 'self'; \
script-src 'self'; \
style-src 'self'; \
img-src 'self'; \
connect-src 'self'; \
font-src 'self'; \
base-uri 'none'; \
form-action 'self'; \
frame-ancestors 'none'; \
object-src 'none'";

const PERMISSIONS_POLICY: &str =
    "geolocation=(), camera=(), microphone=(), interest-cohort=(), browsing-topics=()";
