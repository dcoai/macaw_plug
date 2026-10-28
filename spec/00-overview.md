# 00 — Overview {#plug-overview}

## 1. What macaw_plug holds {#plug-holds}

`macaw_plug` is a host library: request-level guards that every deployable Macaw-family application used to write for itself, three different ways, implemented once (macaw_compose#34). It holds:
- **the client's address behind trusted proxies:** `Macaw.Plug.ClientIp`, over the address and CIDR handling of `Macaw.Plug.Ip` ([01](01-client-ip.md));
- **rate limiting:** `Macaw.Plug.RateLimit`, a generic cell rate algorithm (GCRA) in ETS, as a function and as a plug, with `Macaw.Plug.RateLimit.Table` owning and sweeping its table ([02](02-rate-limit.md));
- **security headers:** `Macaw.Plug.SecurityHeaders`, a closed Content-Security-Policy, per-response script hashes and the standard headers ([03](03-security-headers.md)).

It does not hold an authentication throttle. A request rate per key and exponential backoff after failures are different policies, so the throttle stays in `macaw_auth`, which uses `Macaw.Plug.ClientIp` for its per-address key (macaw_compose#34, owner decision).

## 2. Dependencies {#plug-dependencies}

- **Runtime:** `plug` and `telemetry` (which `plug` itself depends on). No Phoenix, Ecto or JSON library (macaw_compose#34).
- **Test only:** `stream_data`, for the property tests.
- **Elixir** 1.18 or newer; the `:logger` application.

A host uses `macaw_plug` alone or beside `macaw_host` and `macaw_auth`; none of the composition libraries (`macaw_layers`, `macaw_data`, `macaw_compose`, `macaw_live`) depends on it ([macaw_compose 00 §4](https://github.com/dcoai/macaw/blob/main/spec/00-overview.md#overview-packaging)). It is released by git tag (v0.1.2).

## 3. Defaults are closed {#plug-closed}

Every option that grants trust or loosens a policy defaults to granting nothing, and a host widens it only by naming what it widens, so every loosening is visible in the host's code:
- **trusted proxies default to none** ([01 §3](01-client-ip.md#plug-client-ip-config)): behind an undeclared proxy every client looks like the proxy, which is wrong but never spoofable;
- **the default policy is closed** ([03 §1](03-security-headers.md#plug-headers-policy)): everything from the app's own origin, nothing inline, nothing evaluated, nothing framed;
- **a directive changes only by naming it** ([03 §2](03-security-headers.md#plug-headers-overrides)), and an inline script is allowed only by its hash, never by `'unsafe-inline'`;
- **a rate limiter has no default rate:** `rate:` is required ([02 §2](02-rate-limit.md#plug-rate-new)).

## 4. Where the plugs go {#plug-pipeline}

`Macaw.Plug.ClientIp` runs first, so everything after it (logging, `Macaw.Plug.RateLimit` keyed by address, `macaw_auth`'s throttle) reads the client's address from `conn.remote_ip`:

```elixir
plug Macaw.Plug.ClientIp, trusted_proxies: ["10.0.0.0/8"]
plug Macaw.Plug.RateLimit, id: :site, rate: {10, :second}, burst: 50
plug Macaw.Plug.SecurityHeaders
```

`Macaw.Plug.RateLimit.Table` is started once in the host's supervision tree before any limiter is checked ([02 §5](02-rate-limit.md#plug-rate-table)). `Macaw.Plug.SecurityHeaders` replaces Phoenix's `put_secure_browser_headers`.
