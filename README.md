# macaw_plug

> **This software is a very early release, and not ready for general use.**

Public home: [github.com/dcoai/macaw_plug](https://github.com/dcoai/macaw_plug) · Docs: [hexdocs.pm](https://hexdocs.pm/macaw_plug)

Request guards for Phoenix and Plug hosts, implemented once for the Macaw family's host applications (dco-tek/macaw_compose#34). Plug only: no Phoenix, Ecto or JSON dependency.

| Module | What it does |
|---|---|
| `Macaw.Plug.ClientIp` | the client's address behind trusted proxies (none trusted by default); sets `conn.remote_ip` |
| `Macaw.Plug.Ip` | address and CIDR parsing, membership, IPv4-mapped normalization |
| `Macaw.Plug.RateLimit` | GCRA rate limiting in ETS, by client address or any key; `429` with `Retry-After` (start `Macaw.Plug.RateLimit.Table` in the host's tree) |
| `Macaw.Plug.SecurityHeaders` | a closed Content-Security-Policy, script hashes added per response, and the standard headers; replaces Phoenix's `put_secure_browser_headers` |

```elixir
plug Macaw.Plug.ClientIp, trusted_proxies: ["10.0.0.0/8"]
plug Macaw.Plug.RateLimit, id: :site, rate: {10, :second}, burst: 50
plug Macaw.Plug.SecurityHeaders
```

Part of [Macaw](https://github.com/dcoai/macaw), whose spec lists it among the host libraries (spec/00 §4). From Hex:

```elixir
{:macaw_plug, "~> 0.1.4"}
```
