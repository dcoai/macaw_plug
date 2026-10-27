# macaw_plug specification

`macaw_plug` holds the request guards every Macaw host application needs: the client's address behind trusted proxies, rate limiting, and security headers with a closed Content-Security-Policy. Each Macaw component has its own spec in its own repository (dco-tek/macaw_compose#61); this is `macaw_plug`'s. The family's overview, and where the host libraries sit in it, is in [macaw_compose 00 §4](https://gitlab.conet.yarina.org/dco-tek/macaw_compose/-/blob/main/spec/00-overview.md#overview-packaging).

| File | Covers | Status |
|---|---|---|
| [00 — Overview](00-overview.md) | what `macaw_plug` holds, its dependencies, closed defaults, where the plugs go in a pipeline, known gaps | |
| [01 — Client address](01-client-ip.md) | `Macaw.Plug.Ip` (addresses, CIDRs, IPv4-mapped normalization) and `Macaw.Plug.ClientIp` (the right-most-untrusted rule, trusted proxies, the untrusted-forward event and its logger) | implemented (v0.1.0) |
| [02 — Rate limiting](02-rate-limit.md) | `Macaw.Plug.RateLimit` (GCRA, `new/2`, `check/3`, the plug) and `Macaw.Plug.RateLimit.Table` (the table and its sweep) | implemented (v0.1.0) |
| [03 — Security headers](03-security-headers.md) | `Macaw.Plug.SecurityHeaders` (the closed default policy, directive overrides, script hashes, the standard headers, HSTS) | implemented (v0.1.2) |

Every heading carries an anchor prefixed `plug-`, so links into this spec stay stable when a heading is reworded. Each behavioral rule carries a test hint (a fenced block whose info string is `test:<id>`) that says what a test of it must show.
