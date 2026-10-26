# macaw_plug

Request guards for Phoenix and Plug hosts, implemented once for the Macaw family's host applications (dco-tek/macaw_compose#34). Plug only: no Phoenix, Ecto or JSON dependency.

| Module | What it does |
|---|---|
| `Macaw.Plug.ClientIp` | the client's address behind trusted proxies (none trusted by default); sets `conn.remote_ip` |
| `Macaw.Plug.Ip` | address and CIDR parsing, membership, IPv4-mapped normalization |

```elixir
plug Macaw.Plug.ClientIp, trusted_proxies: ["10.0.0.0/8"]
```

Part of [Macaw](https://gitlab.conet.yarina.org/dco-tek/macaw_compose), whose spec lists it among the host libraries (spec/00 §4). Released by git tag:

```elixir
{:macaw_plug, git: "git@gitlab.conet.yarina.org:dco-tek/macaw_plug.git", tag: "v0.1.0"}
```
