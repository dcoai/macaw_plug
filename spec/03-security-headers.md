# 03 — Security headers {#plug-headers}

<!-- surfex: class chapter-intro -->

`Macaw.Plug.SecurityHeaders` writes a strict Content-Security-Policy and the standard security headers on every response. It comes from macaw's `PageScripts` (the closed policy and script hashing) and Snow's `SecurityHeaders` (the standard headers, HSTS over https), and replaces Phoenix's `put_secure_browser_headers` (macaw_compose#34, #45).

## 1. The default policy {#plug-headers-policy}

**The default policy is closed:** everything from the app's own origin, nothing inline, nothing evaluated, nothing framed. With no options, `content-security-policy` is exactly:

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

- The directives are in that order, each `name value`, joined by `"; "`.
- It contains no `'unsafe-inline'` and no `'unsafe-eval'`.

`Macaw.Plug.SecurityHeaders.policy/2` renders a policy from directives (a keyword list, the defaults when omitted) and script hashes (none when omitted). A directive's name is its key with `_` written as `-` (`img_src` is `img-src`).

```test:headers-default-policy
with no options the policy is exactly the string above, and contains no "unsafe"
```

## 2. Changing a directive {#plug-headers-overrides}

**A directive changes only by naming it:** `csp: [img_src: "'self' https://tiles.example"]` replaces `img-src`'s value and nothing else, so every loosening is visible in the host's code. An override:
- **replaces the directive where it stands,** so the policy keeps one order whatever is changed;
- of a directive the defaults lack (`worker_src`, say) is **added after the defaults,** in the order given;
- is `{atom, string}`; anything else raises `ArgumentError` at `init/1`, `"csp: <entry> is not {directive, value}"`.

An override may tighten or loosen a directive; the plug doesn't judge the value. (The work item asked that an override could tighten while the default stays closed; the merged code takes any value, so loosening is allowed and visible by name, macaw_compose#45.)

```test:headers-override-in-place
csp: [img_src: "'self' https://tiles.example"] gives "img-src 'self' https://tiles.example;" in img-src's place, with default-src unchanged
```

```test:headers-override-added
csp: [worker_src: "'self'"] gives the ten default directives in order, then "worker-src 'self'"
```

```test:headers-override-raises
init(csp: ["img-src"]) raises ArgumentError matching `csp: "img-src"`
```

## 3. Inline scripts by hash {#plug-headers-hashes}

**A host's own inline script is allowed by its SHA-256 hash, never by `'unsafe-inline'`.**
- `Macaw.Plug.SecurityHeaders.hash/1` is a script body's CSP hash source: `'sha256-` + the base64 of the SHA-256 of the body, exactly as given, + `'`. The body is the text between `<script>` and `</script>`, byte for byte.
- `Macaw.Plug.SecurityHeaders.put_script_hash/2` allows one inline script on this response: it adds the body's hash to the response's list. A hash already in the list is not added again; the list keeps the order hashes were first added.
- **The policy is written just before the response is sent** (§4), so a controller that renders an inline script adds its hash after the plug has run, and the hash reaches the policy.
- The hashes are added to `script-src`, after its value: `script-src 'self' 'sha256-…' 'sha256-…'`.
- **A policy without `script-src`** (the compatible preset's, §7) falls back to `default-src` in the browser. If it has `default-src`, the hashes go into a `script-src` written right after `default-src`, as `default-src`'s value then the hashes: the fallback made explicit, with the hashes added. If it has neither, it restricts no script, so no `script-src` is written: one of hashes alone would forbid every other script on the page (#1).
- A hash put on the conn **before** the plug runs is kept too (§4, macaw_compose#69).

```test:headers-hash-vector
hash("alert(1)") is "'sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='" (openssl dgst -sha256 -binary | base64)
```

```test:headers-hash-once
the same body put twice after the plug ran gives one hash, in script-src after 'self'
```

```test:headers-two-hashes
bodies "a()" then "b()" give "script-src 'self' <hash a()> <hash b()>;"
```

```test:headers-hash-fallback
under preset: :compatible a hash writes no script-src; with csp: [default_src: "'self'"] added it writes "default-src 'self'; script-src 'self' <hash>" at the end of the policy
```

## 4. When the headers are written {#plug-headers-call}

`Macaw.Plug.SecurityHeaders.init/1` takes `:preset` (§7), `:csp` (§2), `:csp_mode` (§8), `:permissions` (§9), `:headers` (§6) and `:hsts` (§5). **Any other option raises** `ArgumentError` at `init/1`, naming the entry and listing the options: a misspelled option would otherwise leave its default in place without a word (#1). `Macaw.Plug.SecurityHeaders.call/2` keeps any hashes already added to the conn (`put_script_hash/2` may run before the plug, macaw_compose#69) and registers a `register_before_send` callback; nothing is written until the response is sent. Then, in this order:
1. the policy, from the directives and every hash added by then, before or after the plug ran, under the header `csp_mode:` names (§8; none with `:off`);
2. the headers: the standard headers (§6), the Permissions-Policy (§9) and, over https, `strict-transport-security` (§5), with the host's replacements and removals (`headers:`) applied to all of them alike.

```test:headers-unknown-option
init(csp_mod: :off) raises ArgumentError naming {:csp_mod, :off}
```

```test:headers-hash-before-plug
a hash added with put_script_hash/2 before the plug runs is in the policy's script-src
```

Each is written with `put_resp_header`, replacing any value of the same name a controller set earlier.

```test:headers-every-response
every response through the plug carries content-security-policy and the five standard headers of §6
```

## 5. HSTS over https only {#plug-headers-hsts}

Over https (`conn.scheme == :https`) the response carries `strict-transport-security`, `max-age=31536000` by default. Over http it carries none, since a browser ignores it there. Behind a TLS-terminating proxy, `conn.scheme` is https only if the host rewrites it (`Plug.RewriteOn`, say).

`hsts:` sets the default value; a value that is not a string (`nil`, `false`) turns HSTS off. **HSTS is one of the headers** (macaw_compose#69): over https, an entry for `strict-transport-security` in `headers:` replaces it, and `nil` removes it, as for any header (§6). Over http it is never sent, whatever `headers:` says.

```test:headers-hsts-via-headers
over https, headers: %{"strict-transport-security" => nil} sends none, and => "max-age=60" sends max-age=60
```

```test:headers-hsts
over http there is no strict-transport-security; over https it is "max-age=31536000"; with hsts: nil there is none over https
```

## 6. The standard headers {#plug-headers-standard}

Every response also carries:

| Header | Value |
|---|---|
| `x-content-type-options` | `nosniff` |
| `referrer-policy` | `strict-origin-when-cross-origin` |
| `x-frame-options` | `DENY` (for browsers that predate `frame-ancestors`) |
| `cross-origin-opener-policy` | `same-origin` |
| `permissions-policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=()`, rendered from the default features (§9) |

That is the strict preset's set; the compatible preset's is in §7.

`headers: %{"name" => value}` changes them by name: **a value replaces** the header, **`nil` removes it**, and a name not in the table **adds** a header. Names are lower-case, as Plug requires. `headers:` applies after `permissions:` is rendered, so `headers: %{"permissions-policy" => …}` replaces the whole rendered policy, and `nil` removes it.

```test:headers-standard
with no options each header of the table has its value
```

```test:headers-replace-remove
headers: %{"x-frame-options" => nil, "referrer-policy" => "no-referrer"} gives no x-frame-options and referrer-policy "no-referrer"
```

```test:headers-permissions-header-wins
headers: %{"permissions-policy" => "x=()"} with permissions: [geolocation: :self] sends exactly "x=()"
```

## 7. The preset {#plug-headers-preset}

**`preset:` is the starting point**, and every other option applies on top of it, so a host can start compatible and opt into each strict piece by name (#1):

- **`:strict`** (the default) is §1's policy and §6's headers.
- **`:compatible`** is the set Phoenix 1.8's `put_secure_browser_headers` sends, plus HSTS over https (§5):

| Header | Value |
|---|---|
| `content-security-policy` | `base-uri 'self'; frame-ancestors 'self'` |
| `x-content-type-options` | `nosniff` |
| `referrer-policy` | `strict-origin-when-cross-origin` |
| `x-permitted-cross-domain-policies` | `none` |

It sends no `x-frame-options`, no `cross-origin-opener-policy` and no `permissions-policy`: its directives are those two and its features none (§9). A directive named in `csp:` replaces one of the two or is added after them; a feature in `permissions:` starts a Permissions-Policy.

Any other preset raises `ArgumentError` at `init/1`, `"preset: <value> is not :strict or :compatible"`.

```test:headers-preset-compatible
preset: :compatible sends exactly the four headers of the table over http, and strict-transport-security too over https
```

```test:headers-preset-on-top
preset: :compatible, csp: [script_src: "'self'"] gives "base-uri 'self'; frame-ancestors 'self'; script-src 'self'"; with permissions: [camera: :none] it sends "camera=()"
```

```test:headers-preset-raises
init(preset: :loose) raises ArgumentError matching "preset: :loose"
```

## 8. The policy's mode {#plug-headers-mode}

**`csp_mode:` decides which header carries the policy**, so a host can try a policy before it enforces it (#1):

- **`:enforce`** (the default) writes it as `content-security-policy`: the browser blocks what it forbids.
- **`:report_only`** writes the same policy, hashes included, as `content-security-policy-report-only`, and no `content-security-policy`: the browser blocks nothing and reports each violation, in its console and, if the host names a directive for it, to the host (`csp: [report_uri: "/csp-reports"]`). Browsers ignore `frame-ancestors` in a report-only policy, so framing is still governed by `x-frame-options` (§6).
- **`:off`** writes no policy header. `put_script_hash/2` still works, and its hashes are unused.

The other headers are the same in every mode. Any other mode raises `ArgumentError` at `init/1`, `"csp_mode: <value> is not :enforce, :report_only or :off"`.

```test:headers-mode-report-only
csp_mode: :report_only sends the default policy, with a hash added, as content-security-policy-report-only, and no content-security-policy
```

```test:headers-mode-off
csp_mode: :off sends neither policy header, and every standard header of §6
```

```test:headers-mode-raises
init(csp_mode: :block) raises ArgumentError matching "csp_mode: :block"
```

## 9. The Permissions-Policy by feature {#plug-headers-permissions}

**A browser feature changes only by naming it**, as a directive does (§2): `permissions: [geolocation: :self]`. The strict preset's features are `camera`, `microphone`, `geolocation`, `payment` and `usb`, in that order, each `:none`; the compatible preset's are none. An entry:

- **replaces the feature where it stands**; a feature the preset lacks is **added after them**, in the order given; **`nil` removes it**;
- is `{feature, allowlist}`, with the feature an atom of lower-case letters, digits and `_`, written with `_` as `-` (`display_capture` is `display-capture`);
- has an allowlist of `:none` (`()`), `:self` (`(self)`), `:all` (`*`), or a list of `:self` and origins, written in order inside parentheses, each origin quoted: `[:self, "https://meet.example"]` is `(self "https://meet.example")`. An origin is `http://` or `https://`, a host of letters, digits, `.` and `-`, and an optional port, with nothing after it.

Anything else raises `ArgumentError` at `init/1`: `"permissions: <entry> is not {feature, allowlist}"`, or for an origin, `"permissions: <entry>: <origin> is not an http(s) origin"`.

The features render as `feature=allowlist`, joined by `", "`. When no feature is left (the compatible preset, or every one removed), no `permissions-policy` header is sent.

`Macaw.Plug.SecurityHeaders.permissions_policy/1` renders a policy from entries (the strict defaults when omitted), and raises as `init/1` does on an entry it can't render.

```test:headers-permissions-replace
permissions: [geolocation: :self] gives "camera=(), microphone=(), geolocation=(self), payment=(), usb=()"
```

```test:headers-permissions-added
permissions: [display_capture: :none] adds "display-capture=()" after usb, and [usb: nil] removes usb
```

```test:headers-permissions-allowlists
[camera: [:self, "https://meet.example"]] renders camera=(self "https://meet.example"); :all renders *; removing every feature sends no permissions-policy
```

```test:headers-permissions-raises
a string feature, a feature with "-", an unknown allowlist, a list holding an atom other than :self, and the origins "https://a.example/path", "ftp://a.example" and ~s(https://a"b) each raise ArgumentError naming the entry
```
