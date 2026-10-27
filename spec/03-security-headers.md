# 03 — Security headers {#plug-headers}

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
- The list starts empty when the plug runs, so a hash put on the conn **before** the plug runs is dropped.

```test:headers-hash-vector
hash("alert(1)") is "'sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='" (openssl dgst -sha256 -binary | base64)
```

```test:headers-hash-once
the same body put twice after the plug ran gives one hash, in script-src after 'self'
```

```test:headers-two-hashes
bodies "a()" then "b()" give "script-src 'self' <hash a()> <hash b()>;"
```

## 4. When the headers are written {#plug-headers-call}

`Macaw.Plug.SecurityHeaders.init/1` takes `:csp` (§2), `:headers` (§6) and `:hsts` (§5). `Macaw.Plug.SecurityHeaders.call/2` starts the response's hash list empty and registers a `register_before_send` callback; nothing is written until the response is sent. Then, in this order:
1. `content-security-policy`, from the directives and the hashes added by then;
2. the standard headers (§6), with the host's replacements and removals;
3. `strict-transport-security`, over https (§5).

Each is written with `put_resp_header`, replacing any value of the same name a controller set earlier.

```test:headers-every-response
every response through the plug carries content-security-policy and the five standard headers of §6
```

## 5. HSTS over https only {#plug-headers-hsts}

Over https (`conn.scheme == :https`) the response carries `strict-transport-security`, `max-age=31536000` by default. Over http it carries none, since a browser ignores it there. Behind a TLS-terminating proxy, `conn.scheme` is https only if the host rewrites it (`Plug.RewriteOn`, say).

`hsts:` replaces the value; a value that is not a string (`nil`, `false`) turns HSTS off. HSTS is written after the `headers:` map (§4), so over https an entry for `strict-transport-security` in `headers:` has no effect; `hsts:` is the one way to change it.

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
| `permissions-policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` |

`headers: %{"name" => value}` changes them by name: **a value replaces** the header, **`nil` removes it**, and a name not in the table **adds** a header. Names are lower-case, as Plug requires.

```test:headers-standard
with no options each header of the table has its value
```

```test:headers-replace-remove
headers: %{"x-frame-options" => nil, "referrer-policy" => "no-referrer"} gives no x-frame-options and referrer-policy "no-referrer"
```
