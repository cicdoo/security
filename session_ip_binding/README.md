# Session IP binding

Binds each authenticated session to the client IP seen on its first request.
If a later request arrives from a different IP, the session is logged out, a
warning is logged and the user is sent to the login page. This limits the use
of session cookies leaked by malware.

* Settings (General Settings): enable/disable, mode `exact` or `subnet`
  (/24 IPv4, /64 IPv6).
* Requires `proxy_mode = True` behind a reverse proxy that sets
  `X-Forwarded-For`, otherwise the proxy IP is bound.
* Sessions already open at install time are bound on their next request.
* Limits: users changing IP (mobile, VPN) are logged out; an attacker behind
  the same IP/NAT is not blocked; websocket/bus connections do not pass
  through `_authenticate_explicit` and are not checked; API keys are untouched.

## Proxy trust and normalisation

* Behind a proxy, `proxy_mode` must be on **and** the proxy must overwrite
  (not append to) `X-Forwarded-For`; otherwise clients can spoof their IP.
  With `proxy_mode` off, all users share the proxy IP and binding is useless.
* Requests without a client IP are neither bound nor checked (debug log).
* IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) are treated as the plain IPv4.
* Unknown `mode` values behave as `exact`.

## Security and performance review

* Revocation logs out the session and rotates it in the store, so the old
  cookie is dead. The warning log contains IP and path (useful for audit).
* Not covered: websocket/bus and API-key auth (see Limits above).
* Performance: the check does two cached `get_param` lookups per authenticated
  request and writes the session only on the first (binding) request. No
  significant cost found.
