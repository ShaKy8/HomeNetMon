# Security Guide

## Trust model

HomeNetMon assumes a **trusted LAN**. There is no login and no user model: anyone who can reach the
port can read every page and change settings. This is deliberate (see `CLAUDE.md`); do not add
authentication, add network boundaries instead:

- Bind to the LAN only (`HOST=0.0.0.0` on the LAN interface; never port-forward 5000).
- For remote access use a VPN or an overlay network (WireGuard, Tailscale), or a reverse proxy that
  terminates TLS **and** authenticates (Caddy + basic auth, nginx + auth_request, Authelia).
- Keep the host's firewall closed to everything but the LAN.

## What the application does protect

- **CSRF.** Every state-changing request needs an `X-CSRF-Token` header (stateless HMAC, one hour).
  Cookies alone are never accepted, so a malicious page on another origin cannot act on your behalf.
- **Security headers.** `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy` on every response. The CSP still allows inline scripts because templates carry them.
- **Rate limiting.** Per-route tiers (`relaxed` 120/min … `critical` 1 per 5 min). Localhost and
  `RATE_LIMIT_TRUSTED_IPS` are exempt. Storage is in-memory unless `REDIS_URL` points at a reachable Redis.
- **Input validation.** Device-control actions (wake-on-LAN, port scan, traceroute, discovery) accept
  private addresses only; IPs, MACs, hostnames and configuration values are validated.
- **Output escaping.** Anything a LAN device controls (hostnames, vendors, service banners) is escaped
  before it reaches `innerHTML`.
- **Socket.IO origins.** Only RFC 1918 and `.local` origins may connect.

## What it does not protect

- Confidentiality on the wire: HTTP only. Put TLS in front if the LAN is not trusted.
- Anything once an attacker is on the LAN: they can change settings, delete alerts, trigger scans.

## Scanner side effects

The security scanner runs nmap `-sV` port scans against every monitored device. That is intrusive:
some cameras and printers reset or hang. Printers are excluded by default; disable
`SECURITY_SCANNING_ENABLED` if a device misbehaves. Discovery (`-sn`) is harmless.

## Secrets

`SECRET_KEY` signs CSRF tokens; the installer generates one and validation refuses short or well-known
values. Keep `.env` out of version control (it is gitignored). Notification credentials (SMTP, ntfy)
live in `.env` or the runtime configuration table, in clear text: protect the host accordingly.

## Dependencies

`requirements.txt` is pinned; run `pip-audit -r requirements.txt` after bumps (CI does).
