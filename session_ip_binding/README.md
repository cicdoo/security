# Session IP binding

Binds each authenticated session to the client IP seen on its first request,
separately per address family (`bound_ip_v4`, `bound_ip_v6`). Switching between
IPv4 and IPv6 (dual-stack browsers) is never a violation. If a later request
arrives from a different address of the same family, the session is logged out, a
warning is logged and the user is sent to the login page. This limits the use
of session cookies leaked by malware.

* IPv6 is always compared by /64; IPv4-mapped IPv6 is treated as IPv4.
* Settings (General Settings): enable/disable, mode `exact` (full IPv4) or
  `subnet` (IPv4 /24). Both modes bind each family separately.
* Sessions with the legacy `bound_ip` key (exact IP or CIDR) are migrated to the
  matching family key on their next request, so the upgrade logs nobody out.
  A legacy value that cannot be carried over safely (e.g. a /24 while the mode
  is now `exact`) is dropped and that family rebinds on its next request.
* Trade-off: a stolen cookie is accepted from the other address family
  (which then becomes bound too); same-family theft is still blocked.
* Requires `proxy_mode = True` behind a reverse proxy that sets
  `X-Forwarded-For`, otherwise the proxy IP is bound.
* Sessions already open at install time are bound on their next request.
* Limits: users changing IP (mobile, VPN) are logged out; an attacker behind
  the same IP/NAT is not blocked; websocket/bus connections do not pass
  through `_authenticate_explicit` and are not checked; API keys are untouched.
* 18.0 backport: uses `get_param`, `Session.logout` and `http.root.session_store`.
