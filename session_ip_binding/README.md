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
