# 01 — Client address {#plug-client-ip}

Behind a reverse proxy, the socket's peer is the proxy, and the client's address arrives in `X-Forwarded-For`, which anyone can write. `Macaw.Plug.ClientIp` decides which entry to believe, from the proxies the host declares, and `Macaw.Plug.Ip` does the address arithmetic. Both start from macaw's and exio's copies of the same rule (macaw_compose#34, #43).

## 1. Addresses and CIDRs {#plug-ip}

`Macaw.Plug.Ip` parses, formats, normalizes and matches addresses. An address is an `:inet.ip_address()` tuple (`Macaw.Plug.Ip.ip()`); a CIDR is `{network, prefix}` (`Macaw.Plug.Ip.cidr()`), the prefix in `0..32` for IPv4 and `0..128` for IPv6.

### 1.1 Parsing an address {#plug-ip-parse}

- `Macaw.Plug.Ip.parse/1` trims the text, parses it strictly (`:inet.parse_strict_address/1`: no shortened IPv4 forms such as `"10.1"`), and returns the address normalized (§1.3), or `nil` for anything else. It never raises on a string.

```test:ip-parse
"203.0.113.9" gives {203, 0, 113, 9}; " 2001:db8::42 " gives the IPv6 tuple; "::ffff:203.0.113.5" gives {203, 0, 113, 5}; "not-an-ip", "10.1" and "" give nil
```

### 1.2 Parsing a CIDR {#plug-ip-parse-cidr}

`Macaw.Plug.Ip.parse_cidr/1` takes `"network/prefix"` or a single address, trimmed:
- **a single address** is a CIDR of one: a /32 for IPv4, a /128 for IPv6;
- **a prefix** must be a whole decimal number in the address family's range;
- the network is kept as written: `"10.1.2.3/8"` is `{{10, 1, 2, 3}, 8}`, and matching masks it (§1.4);
- the result is `{:ok, cidr}` or `{:error, message}`, the message quoting the text:

| Input | Result |
|---|---|
| `"192.0.2.1"` | `{:ok, {{192, 0, 2, 1}, 32}}` |
| `"2001:db8::/32"` | `{:ok, {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}}` |
| `"10.0.0.0/40"` | `{:error, ~s("10.0.0.0/40" has a prefix outside 0..32)}` |
| `"10.0.0.0/x"` | `{:error, ~s("10.0.0.0/x" has a prefix that is not a number)}` |
| `"proxy.local"` | `{:error, ~s("proxy.local" is not an address or a CIDR)}` |
| `"1/2/3"` | `{:error, ~s("1/2/3" is not an address or a CIDR)}` |

```test:ip-parse-cidr
each row of the table: a single address is /32 or /128, a prefix out of range or not a number and a host name are errors whose message quotes the input
```

### 1.3 IPv4-mapped normalization {#plug-ip-normalize}

A dual-stack listener can report an IPv4 peer as an IPv4-mapped IPv6 address (`::ffff:203.0.113.5`). `Macaw.Plug.Ip.normalize/1` turns such an address (`{0, 0, 0, 0, 0, 0xFFFF, hi, lo}`) into its IPv4 tuple and returns every other address unchanged, so a trusted IPv4 proxy matches however the socket reported it. Neither source copy did this (macaw_compose#43).

```test:ip-normalize
{0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0005} normalizes to {10, 0, 0, 5}; an IPv4 tuple and an ordinary IPv6 tuple are returned unchanged
```

### 1.4 Membership {#plug-ip-membership}

- `Macaw.Plug.Ip.in_cidr?/2` is true when the address and the network agree in their first `prefix` bits. **Families never match each other:** an IPv4 address is in no IPv6 CIDR and the reverse. A /0 matches every address of its family.
- `Macaw.Plug.Ip.in_any?/2` normalizes the address, then is true when it is in any of the CIDRs; with none, it is false.

```test:ip-membership
{10, 9, 9, 9} is in {{10, 0, 0, 0}, 8} and not in {{11, 0, 0, 0}, 8}; an IPv4 address is never in an IPv6 CIDR; an IPv4-mapped address is in its IPv4 CIDR through in_any?/2; in_any?/2 with no CIDRs is false
```

### 1.5 Formatting {#plug-ip-to-string}

`Macaw.Plug.Ip.to_string/1` formats an address as `:inet.ntoa/1` does (`"203.0.113.9"`, `"2001:db8::42"`). Parsing what it formats gives the same address back.

```test:ip-to-string
to_string/1 then parse/1 is the identity for IPv4 addresses and for IPv6 addresses that are not IPv4-mapped
```

## 2. The right-most-untrusted rule {#plug-client-ip-rule}

`Macaw.Plug.ClientIp.resolve/3` takes the socket peer, the `X-Forwarded-For` entries left to right as sent, and the trusted CIDRs, and returns the client's address:
- **an untrusted peer is its own client:** the peer is not a trusted proxy, so it could have written any header; the entries are ignored;
- **behind a trusted peer, the client is the right-most entry that is not itself a trusted proxy.** Each proxy appends the address it received from, so entries are walked from the right; entries to the left of the first untrusted one could have been written by the client, and are never believed;
- **a malformed entry stops the walk at the peer:** what lies to its left can't be trusted, so the client is the peer itself;
- **every entry trusted** gives the left-most entry, the farthest hop a trusted proxy reported;
- **no entries** gives the peer;
- the peer and every entry are normalized (§1.3) before they are compared, and the result is normalized.

| Peer | `X-Forwarded-For` | Client |
|---|---|---|
| `10.0.0.5` | `198.51.100.7, 203.0.113.9, 10.1.2.3` | `203.0.113.9` |
| `10.0.0.5` | `1.1.1.1, 203.0.113.9` | `203.0.113.9` |
| `10.0.0.5` | `203.0.113.9, not-an-ip` | `10.0.0.5` |
| `10.0.0.5` | `10.9.9.9, 10.1.1.1` | `10.9.9.9` |
| `198.51.100.7` | `203.0.113.9` | `198.51.100.7` |
| `fd00::1` | `2001:db8::42` | `2001:db8::42` |
| `::ffff:10.0.0.5` | `203.0.113.9` | `203.0.113.9` |

(trusted: `10.0.0.0/8`, `fd00::/8`)

```test:client-ip-rows
each row of the table, with 10.0.0.0/8 and fd00::/8 trusted
```

```test:client-ip-never-proxy
property: for a trusted peer and any chain of IPv4 hops, the client is the right-most hop that is not trusted; when every hop is trusted, the client is a trusted address
```

```test:client-ip-untrusted-own
property: for an untrusted peer and any chain of hops, the client is the peer
```

### 2.1 Reading the header {#plug-client-ip-forwarded}

`Macaw.Plug.ClientIp.forwarded_for/1` returns a request's `X-Forwarded-For` entries, left to right: every `x-forwarded-for` header in the order received, each split on commas, each entry trimmed, empty entries dropped.

```test:client-ip-several-headers
two x-forwarded-for headers, "198.51.100.7" then "203.0.113.9", behind a trusted peer, give 203.0.113.9; forwarded_for/1 of "a, ,b" is ["a", "b"]
```

## 3. Trusted proxies {#plug-client-ip-config}

`Macaw.Plug.ClientIp.init/1` takes `:trusted_proxies`:
- **absent, it is `[]`: none trusted.** Every client is then its peer: behind a reverse proxy every visitor looks like the proxy, wrong but never spoofable (macaw_compose#34, owner decision);
- **a static list** of CIDR strings or single addresses (§1.2), or `{address, prefix}` tuples taken as they are. It is parsed once, at `init/1`. A malformed string raises `ArgumentError` at `init/1`, `"trusted_proxies: "` followed by `Macaw.Plug.Ip.parse_cidr/1`'s message naming it; an entry of any other shape raises `"trusted_proxies: <entry> is not an address or a CIDR"`;
- **`{module, function, args}`** (all three of the right types) returning such a list, called on **every request**, for a list that changes at runtime. Its result is parsed on every request, so a malformed entry it returns raises during that request.

```test:client-ip-default-none
init([]) trusts nothing: a request from 10.0.0.5 forwarding for 203.0.113.9 resolves to 10.0.0.5
```

```test:client-ip-init-raises
init/1 with "10.0.0.0/40" raises ArgumentError matching `"10.0.0.0/40" has a prefix outside`; with "proxy.local", matching `"proxy.local" is not an address`
```

```test:client-ip-dynamic
with trusted_proxies {M, :f, []}, a request is resolved against what M.f/0 returns at that request: trusted while it returns ["10.0.0.0/8"], untrusted once it returns []
```

## 4. What the plug sets {#plug-client-ip-call}

`Macaw.Plug.ClientIp.call/2`, for each request:
- sets **`conn.remote_ip` to the client** (§2), so logging, rate limits and everything downstream key on the client's address;
- keeps **the socket peer, normalized, in `conn.private.macaw_plug_peer`;**
- emits the untrusted-forward event when the request forwards from an untrusted peer (§5).

The client is written once, in `conn.remote_ip`; nothing else (no assign) carries it. `Macaw.Plug.ClientIp.peer/1` returns the peer of a request the plug has run on, else the request's `remote_ip`.

```test:client-ip-peer
after the plug, remote_ip is the client and peer/1 is the socket peer ({10, 0, 0, 5} for a trusted peer forwarding for 203.0.113.9); peer/1 of a conn the plug never ran on is its remote_ip
```

## 5. The untrusted-forward event {#plug-client-ip-event}

A request that sent `X-Forwarded-For` (at least one non-empty entry) from a peer that is **not** trusted is served as usual, with the header ignored, and emits the telemetry event `[:macaw_plug, :client_ip, :untrusted_forward]`, measurements `%{count: 1}`, metadata `%{peer: peer}` (the normalized peer). It usually means a proxy in front of the app is missing from the trusted list. A request without the header emits nothing, and neither does a forwarded request from a trusted peer.

```test:client-ip-event
a forwarded request from untrusted 198.51.100.7 emits the event with %{count: 1} and %{peer: {198, 51, 100, 7}}; a request from 198.51.100.8 without the header emits nothing
```

### 5.1 The default logger {#plug-client-ip-logger}

`Macaw.Plug.ClientIp.attach_default_logger/1` attaches a telemetry handler (id `"macaw-plug-client-ip-logger"`, handler `Macaw.Plug.ClientIp.log_untrusted/4`) that logs the event as a warning naming the peer, `"X-Forwarded-For from untrusted peer <peer>; if it is your proxy, add it to trusted_proxies"`:
- **at most once per interval** on the node, `interval_ms` defaulting to one minute; the events between are dropped, not queued;
- **the first event logs at once.** "Never logged" is one interval before the attach, not a fixed sentinel, because BEAM's monotonic clock can be negative (a fixed sentinel kept the first warning from ever firing; found and fixed in macaw_compose#43);
- **concurrent events log once:** the last-logged time is advanced with compare-and-swap, so of two events in the same instant only one logs;
- it returns `:ok`, or `{:error, :already_exists}` when the handler is already attached.

```test:client-ip-logger-once
with the logger attached at 60 000 ms, two untrusted forwards from 198.51.100.7 log one warning naming 198.51.100.7
```
