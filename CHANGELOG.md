# Changelog

## Unreleased

- The macaw logo in the docs and the README (macaw#175).
- `Macaw.Plug.SecurityHeaders` options, all additive; with none, every header is as before (#1):
  - `csp_mode:` `:enforce` (default), `:report_only` or `:off`;
  - `permissions:` changes Permissions-Policy features by name, and `permissions_policy/1` renders one;
  - `preset: :compatible`, Phoenix's `put_secure_browser_headers` set plus HSTS over https, with every other option on top.
- Script hashes on a policy without `script-src` follow `default-src`, or with neither write none, rather than a `script-src` that forbids every other script.
- **Breaking:** an unknown `Macaw.Plug.SecurityHeaders` option raises at `init/1` instead of being ignored.

## v0.1.4 (2026-10-28)

- The README opens with the early-release notice (macaw#174).

## v0.1.3 (2026-10-28)

- Spec and README links to the public home, `github.com/dcoai/macaw_plug`, and the install snippet from Hex (macaw#171, #173).
- Package metadata for Hex: the public home, the changelog link, the files shipped, and docs with `ex_doc` (macaw_compose#155).

## v0.1.2 (2026-10-27)

- Adopt surfex; fix policy/2's empty script-src; v0.1.2 (part of macaw_compose#65)

## v0.1.1 (2026-10-27)

- macaw_plug 0.1.1: HSTS through headers:, hashes before the plug, dynamic proxy lists never raise

## v0.1.0 (2026-10-26)

- macaw_plug 0.1.0: ClientIp, RateLimit, SecurityHeaders
