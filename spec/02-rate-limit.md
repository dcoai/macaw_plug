# 02 — Rate limiting {#plug-rate}

<!-- surfex: class chapter-intro -->

`Macaw.Plug.RateLimit` is one limiter for every request rate a host enforces: an API's, a form's, a page's. It is exio's generic cell rate algorithm, generalized from exio's fixed API limit to named limiters keyed by whatever the caller names (macaw_compose#34, #44). It replaced three algorithms in three projects (exio's GCRA and two fixed windows).

## 1. The algorithm {#plug-rate-gcra}

A limiter allows `count` requests per `period` on average, and bursts of up to `burst` at once:
- **the emission interval** is `period / count`, in whole microseconds, at least 1;
- **the tolerance** is `(burst - 1) × interval`;
- **each key has one theoretical arrival time** (TAT), the time at which it would have its full burst again;
- a request for a key at `now` is **allowed** when `max(TAT, now) - now ≤ tolerance`, and then the TAT becomes `max(TAT, now) + interval`;
- a request is **refused** otherwise, and the TAT is left as it was: a refused request costs nothing;
- **a key never seen** is allowed, with TAT `now + interval`.

So a key idle long enough has its full burst; after a burst, one request is allowed per interval.

```test:rate-burst-then-interval
rate {10, :second}, burst 3, all at t = 0: three requests allowed, the fourth refused with {:error, 1}; at t = 100 ms exactly one more is allowed and the next refused
```

```test:rate-keys-independent
rate {1, :minute}: key :a is allowed once, then refused with {:error, 60}; key :b is still allowed at the same instant
```

```test:rate-window-bound
property: for any count in 1..20, burst in 1..10 and arrival times, the requests allowed never exceed burst + span × count / period + 1, span being the time from the first arrival to the last
```

### 1.1 Compare-and-swap {#plug-rate-cas}

The TAT is advanced with compare-and-swap, never read-then-write: the new TAT replaces the row only if the row still holds the TAT the decision was made on, and a key's first row is inserted only if none exists. A request that loses the race decides again against the row as it now is. So **concurrent requests on one key can never both take the last slot.**

```test:rate-concurrent
200 concurrent checks of one key at one instant, rate {1, :hour} and burst 25: exactly 25 are allowed
```

## 2. A limiter {#plug-rate-new}

`Macaw.Plug.RateLimit.new/2` makes a limiter, `%Macaw.Plug.RateLimit{id, interval, tolerance}`:
- `id`, any term, names it. Limiters share one table, each key stored as `{id, key}`, so two limiters never share a key;
- **`rate: {count, period}` is required:** `count` a positive integer, `period` `:second`, `:minute` or `:hour`;
- `burst:` is a positive integer, `count` by default;
- a rate it can't honor raises `ArgumentError` naming it: `"rate: {0, :second} is not {count, :second | :minute | :hour}"`, `"burst: 0 is not a positive integer"`.

```test:rate-new-raises
new/2 raises ArgumentError matching `rate: {0, :second}` for a zero count, `rate: {5, :day}` for an unknown period, and `burst: 0` for a zero burst
```

## 3. Checking {#plug-rate-check}

`Macaw.Plug.RateLimit.check/3` takes a slot for a key at `now`, in monotonic microseconds (default `System.monotonic_time(:microsecond)`), and returns:
- `:ok` when the request is allowed (§1);
- `{:error, seconds}` when it is refused, `seconds` being the time until a slot frees, **rounded up to a whole second and at least 1.**

It needs the table (§5) running; without it, it raises.

```test:rate-wait
rate {1, :minute}: allowed at 0; refused at 0 with {:error, 60}; refused 1 µs before the minute with {:error, 1}; allowed at exactly 60 s
```

## 4. The plug {#plug-rate-plug}

`Macaw.Plug.RateLimit.init/1` takes `:id` (required), `:rate` and `:burst` (as `new/2`, raising as it does), and:
- **`:key`**, what requests are counted by: `:client_ip` (the default) counts by `conn.remote_ip`, the client's address once `Macaw.Plug.ClientIp` has run ([01 §4](01-client-ip.md#plug-client-ip-call)); `{module, function}` counts by `module.function(conn)`, any term (a token, a user, a route);
- **`:on_limit`**, `{module, function}` answering a refused request instead of the default;
- **`:now`**, the clock: `:monotonic` (the default) or a zero-arity function returning monotonic microseconds, for a test.

`Macaw.Plug.RateLimit.call/2` checks the request's key at the clock's time:
- **allowed,** the conn passes on unchanged;
- **refused,** by default: a `retry-after` header with the seconds to wait, `content-type: text/plain`, status **429**, body `"Too many requests; retry in <seconds> s.\n"`, and the conn halted;
- **refused with `:on_limit`:** the `retry-after` header is set, then `module.function(conn, seconds)` answers (a JSON API's error shape, say; it sends the response), and the conn is halted.

```test:rate-plug-429
rate {1, :minute} and a fixed clock: the first request from 203.0.113.9 passes, the second is halted with 429 and retry-after "60"; a request from 198.51.100.7 still passes
```

```test:rate-plug-key-on-limit
with key: {M, :by_header} and on_limit: {M, :json_429}, the second request on one key is answered by json_429 with the seconds to wait (status 429, its JSON body)
```

### 4.1 The clock is resolved in call/2 {#plug-rate-clock}

Plug may run `init/1` at compile time and embed its result in the compiled pipeline. So `init/1` keeps the clock as `:monotonic` or a function, and **`call/2` reads it on every request**: a time read in `init/1` would be frozen into the build (exio's #101).

```test:rate-clock-per-call
two requests through one init/1 result read the :now function at each call: with a clock that advances by a minute between them, rate {1, :minute} allows both
```

## 5. The table and its sweep {#plug-rate-table}

`Macaw.Plug.RateLimit.Table` owns the limiters' ETS table, `Macaw.Plug.RateLimit.Table` (named, public, a set, with read and write concurrency). A host starts it once in its supervision tree, before any limiter is checked (`Macaw.Plug.RateLimit.Table.start_link/1`, registered under its module name). The table lives as long as that process; a restart starts it empty, so every key has its full burst again.

**The sweep keeps memory to the active keys.** A key whose TAT has passed has its full burst again, so it is the same as an absent key. `Macaw.Plug.RateLimit.Table.sweep/1` deletes every row whose TAT is before `now` (monotonic microseconds, default the clock) and returns how many it deleted. The table runs it every `:sweep_every` milliseconds (default one minute). exio's table only grew (macaw_compose#44).

A sweep racing a check is safe: the check's compare-and-swap (§1.1) finds the row gone and decides again, as for a key never seen.

```test:rate-sweep
a key last checked at 0 and one at 10 s, rate {1, :second}: sweep(5 s) deletes the first and keeps the second
```
