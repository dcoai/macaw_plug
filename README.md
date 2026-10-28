<img src="brand/logo/macaw_scarlet.svg" alt="The Macaw logo, a scarlet macaw in flight" width="128">

# macaw_plug

> **This software is a very early release, and not ready for general use.**

Public home: [github.com/dcoai/macaw_plug](https://github.com/dcoai/macaw_plug) · Docs: [hexdocs.pm](https://hexdocs.pm/macaw_plug)

Request guards for Phoenix and Plug hosts, implemented once for the Macaw family's host applications (dco-tek/macaw_compose#34). Plug only: no Phoenix, Ecto or JSON dependency.

| Module | What it does |
|---|---|
| `Macaw.Plug.ClientIp` | the client's address behind trusted proxies (none trusted by default); sets `conn.remote_ip` |
| `Macaw.Plug.Ip` | address and CIDR parsing, membership, IPv4-mapped normalization |
| `Macaw.Plug.RateLimit` | GCRA rate limiting in ETS, by client address or any key; `429` with `Retry-After` (start `Macaw.Plug.RateLimit.Table` in the host's tree) |
| `Macaw.Plug.SecurityHeaders` | a closed Content-Security-Policy, script hashes added per response, the standard headers and a Permissions-Policy by feature; replaces Phoenix's `put_secure_browser_headers` |

```elixir
plug Macaw.Plug.ClientIp, trusted_proxies: ["10.0.0.0/8"]
plug Macaw.Plug.RateLimit, id: :site, rate: {10, :second}, burst: 50
plug Macaw.Plug.SecurityHeaders
```

## Security headers

The default is closed, and every loosening is named in the host's code:

| Option | Default | |
|---|---|---|
| `preset:` | `:strict` | `:compatible` starts from Phoenix's `put_secure_browser_headers` set, plus HSTS over https |
| `csp:` | `[]` | directives by name, `[img_src: "'self' https://tiles.example"]` |
| `csp_mode:` | `:enforce` | `:report_only` reports violations and blocks nothing; `:off` sends no policy |
| `permissions:` | `[]` | Permissions-Policy features by name: `[geolocation: :self, camera: [:self, "https://meet.example"]]`; `nil` removes one |
| `headers:` | `%{}` | any header by name; `nil` removes it |
| `hsts:` | `"max-age=31536000"` | over https; not a string turns it off |

Every option applies on top of the preset; an unknown option raises.

### Migrating from `put_secure_browser_headers`

1. Swap the plug in with `preset: :compatible`: the same headers Phoenix sends, so nothing breaks.
2. Try the closed policy unenforced: drop the preset and set `csp_mode: :report_only`. The browser console lists what it would block; `csp: [report_uri: "/csp-reports"]` sends the reports to the host.
3. Allow what the pages need, by name: an inline script by its hash (`Macaw.Plug.SecurityHeaders.put_script_hash/2`), a source with `csp:`, a browser feature with `permissions:`. Phoenix's live-reload iframe needs, in development only, `csp: [frame_ancestors: "'self'"]` and `headers: %{"x-frame-options" => "SAMEORIGIN"}`.
4. Enforce: drop `csp_mode:`.

The full rules are in [spec/03](https://github.com/dcoai/macaw_plug/blob/main/spec/03-security-headers.md).

Part of [Macaw](https://github.com/dcoai/macaw), whose spec lists it among the host libraries (spec/00 §4). From Hex:

```elixir
{:macaw_plug, "~> 0.1.4"}
```
