defmodule Macaw.Plug.SecurityHeaders do
  @moduledoc """
  A strict Content-Security-Policy and the standard security headers.

      plug Macaw.Plug.SecurityHeaders

  **The default policy is closed:** everything from the app's own origin,
  nothing inline, nothing evaluated, nothing framed:

      default-src 'self'; script-src 'self'; style-src 'self';
      img-src 'self' data:; font-src 'self'; connect-src 'self';
      object-src 'none'; base-uri 'none'; form-action 'self';
      frame-ancestors 'none'

  A host changes a directive only by naming it, `csp: [img_src: "'self'"]`,
  so every loosening is visible in the host's code.

  **A host's own inline script** is allowed by its SHA-256 hash, never by
  `'unsafe-inline'`. The policy is written just before the response is sent,
  so a controller that renders such a script adds its hash on the way:

      conn |> Macaw.Plug.SecurityHeaders.put_script_hash(script_body)

  **Also set:** `x-content-type-options: nosniff`, `referrer-policy:
  strict-origin-when-cross-origin`, `x-frame-options: DENY` (for browsers
  that predate `frame-ancestors`), `cross-origin-opener-policy:
  same-origin`, a `permissions-policy` that turns off camera, microphone,
  geolocation, payment and USB, and over https
  `strict-transport-security: max-age=31536000`. Each can be replaced with
  `headers: %{"name" => value}`, or removed with `nil`. This replaces
  Phoenix's `put_secure_browser_headers`.

  ## Options

  | Option | Default | |
  |---|---|---|
  | `preset:` | `:strict` | `:compatible` starts from Phoenix's `put_secure_browser_headers` set |
  | `csp:` | `[]` | directives by name, `[img_src: "'self' https://tiles.example"]` |
  | `csp_mode:` | `:enforce` | `:report_only` reports violations and blocks nothing; `:off` sends no policy |
  | `permissions:` | `[]` | Permissions-Policy features by name, `[geolocation: :self]`; `nil` removes one |
  | `headers:` | `%{}` | any header by name; `nil` removes it |
  | `hsts:` | `"max-age=31536000"` | over https; not a string turns it off |

  Every option applies on top of the preset, and an unknown option raises.

  **Permissions** are allowlists: `:none` (`()`), `:self` (`(self)`), `:all`
  (`*`), or a list of `:self` and `http(s)://` origins:
  `permissions: [camera: [:self, "https://meet.example"]]` gives
  `camera=(self "https://meet.example")`.

  ## Migrating from `put_secure_browser_headers`

  1. Start with `preset: :compatible`: the headers Phoenix sends, plus HSTS
     over https. Nothing a Phoenix page did stops working.
  2. Try the closed policy without enforcing it: `csp_mode: :report_only`
     (with the strict preset) sends it as
     `content-security-policy-report-only`, so the browser console lists
     what it would block. Add `csp: [report_uri: "/csp-reports"]` to collect
     the reports.
  3. Allow what the pages need by name: an inline script by its hash
     (`put_script_hash/2`), a directive with `csp:`, a browser feature with
     `permissions:`. Phoenix's live-reload iframe needs, in development
     only, `csp: [frame_ancestors: "'self'"]` and
     `headers: %{"x-frame-options" => "SAMEORIGIN"}`.
  4. Enforce: drop `csp_mode:` (and `preset:`).
  """

  @behaviour Plug

  import Plug.Conn

  @options [:preset, :csp, :csp_mode, :permissions, :headers, :hsts]

  @directives [
    default_src: "'self'",
    script_src: "'self'",
    style_src: "'self'",
    img_src: "'self' data:",
    font_src: "'self'",
    connect_src: "'self'",
    object_src: "'none'",
    base_uri: "'none'",
    form_action: "'self'",
    frame_ancestors: "'none'"
  ]

  @permissions [camera: :none, microphone: :none, geolocation: :none, payment: :none, usb: :none]

  # The starting points (#1): `:strict` is this plug's own, `:compatible` is
  # Phoenix's `put_secure_browser_headers` (1.8), with HSTS over https.
  @presets %{
    strict: %{
      directives: @directives,
      permissions: @permissions,
      headers: %{
        "x-content-type-options" => "nosniff",
        "referrer-policy" => "strict-origin-when-cross-origin",
        "x-frame-options" => "DENY",
        "cross-origin-opener-policy" => "same-origin"
      }
    },
    compatible: %{
      directives: [base_uri: "'self'", frame_ancestors: "'self'"],
      permissions: [],
      headers: %{
        "x-content-type-options" => "nosniff",
        "referrer-policy" => "strict-origin-when-cross-origin",
        "x-permitted-cross-domain-policies" => "none"
      }
    }
  }

  @csp_headers %{
    enforce: "content-security-policy",
    report_only: "content-security-policy-report-only",
    off: nil
  }

  @hsts "max-age=31536000"

  @feature ~r/\A[a-z][a-z0-9_]*\z/
  @origin ~r"\Ahttps?://[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?\z"

  @impl true
  def init(opts) do
    Enum.each(opts, fn
      {k, _} when k in @options ->
        :ok

      other ->
        raise ArgumentError,
              "#{inspect(other)} is not an option; the options are #{inspect(@options)}"
    end)

    preset = Keyword.get(opts, :preset, :strict)

    base =
      Map.get(@presets, preset) ||
        raise ArgumentError, "preset: #{inspect(preset)} is not :strict or :compatible"

    csp_mode = Keyword.get(opts, :csp_mode, :enforce)

    Map.has_key?(@csp_headers, csp_mode) ||
      raise ArgumentError,
            "csp_mode: #{inspect(csp_mode)} is not :enforce, :report_only or :off"

    csp = Keyword.get(opts, :csp, [])

    Enum.each(csp, fn
      {k, v} when is_atom(k) and is_binary(v) -> :ok
      other -> raise ArgumentError, "csp: #{inspect(other)} is not {directive, value}"
    end)

    permissions = Keyword.get(opts, :permissions, [])
    Enum.each(permissions, &check_permission/1)

    rendered =
      case merge_in_place(base.permissions, permissions) do
        [] -> nil
        entries -> permissions_policy(entries)
      end

    %{
      csp_header: Map.fetch!(@csp_headers, csp_mode),
      directives: merge_in_place(base.directives, csp),
      headers:
        base.headers
        |> Map.put("permissions-policy", rendered)
        |> Map.merge(Keyword.get(opts, :headers, %{})),
      hsts: Keyword.get(opts, :hsts, @hsts)
    }
  end

  @impl true
  def call(conn, config) do
    # Hashes added before this plug ran are kept, not reset (#69).
    conn
    |> put_private(
      :macaw_plug_script_hashes,
      Map.get(conn.private, :macaw_plug_script_hashes, [])
    )
    |> register_before_send(fn conn ->
      conn
      |> put_policy(config, conn.private.macaw_plug_script_hashes)
      |> put_headers(headers(conn, config))
    end)
  end

  @doc """
  Allows an inline script on this response by its SHA-256 hash. Takes the
  script's body (the text between `<script>` and `</script>`), exactly.
  """
  @spec put_script_hash(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def put_script_hash(conn, body) when is_binary(body) do
    hashes = Map.get(conn.private, :macaw_plug_script_hashes, [])
    put_private(conn, :macaw_plug_script_hashes, Enum.uniq(hashes ++ [hash(body)]))
  end

  @doc "A script body's CSP hash source, `'sha256-…'`."
  @spec hash(String.t()) :: String.t()
  def hash(body), do: "'sha256-" <> Base.encode64(:crypto.hash(:sha256, body)) <> "'"

  @doc """
  The policy string for directives (the defaults, or as `init/1` merged
  them) and script hashes, which are added to `script-src`.
  """
  @spec policy(keyword(String.t()), [String.t()]) :: String.t()
  def policy(directives \\ @directives, hashes \\ []) do
    directives
    |> add_hashes(hashes)
    |> Enum.map_join("; ", fn {k, v} -> "#{name(k)} #{v}" end)
  end

  @doc """
  The Permissions-Policy string for features and their allowlists (the
  defaults, or as `init/1` merged them):

      iex> Macaw.Plug.SecurityHeaders.permissions_policy(geolocation: :self, camera: :all)
      "geolocation=(self), camera=*"

  An entry that is not `{feature, allowlist}` raises `ArgumentError`.
  """
  @spec permissions_policy(keyword()) :: String.t()
  def permissions_policy(entries \\ @permissions) do
    Enum.map_join(entries, ", ", fn entry ->
      check_permission(entry)
      {feature, allowlist} = entry
      "#{name(feature)}=#{allowlist(allowlist, entry)}"
    end)
  end

  defp check_permission({feature, allowlist} = entry) when is_atom(feature) do
    Regex.match?(@feature, Atom.to_string(feature)) || permission_error(entry)
    allowlist == nil || allowlist(allowlist, entry)
    :ok
  end

  defp check_permission(entry), do: permission_error(entry)

  defp allowlist(:none, _entry), do: "()"
  defp allowlist(:self, _entry), do: "(self)"
  defp allowlist(:all, _entry), do: "*"

  defp allowlist(sources, entry) when is_list(sources),
    do: "(" <> Enum.map_join(sources, " ", &source(&1, entry)) <> ")"

  defp allowlist(_allowlist, entry), do: permission_error(entry)

  defp source(:self, _entry), do: "self"

  defp source(origin, entry) when is_binary(origin) do
    Regex.match?(@origin, origin) ||
      raise ArgumentError,
            "permissions: #{inspect(entry)}: #{inspect(origin)} is not an http(s) origin"

    ~s("#{origin}")
  end

  defp source(_source, entry), do: permission_error(entry)

  defp permission_error(entry),
    do: raise(ArgumentError, "permissions: #{inspect(entry)} is not {feature, allowlist}")

  defp name(key), do: key |> Atom.to_string() |> String.replace("_", "-")

  defp put_policy(conn, %{csp_header: nil}, _hashes), do: conn

  defp put_policy(conn, %{csp_header: header, directives: directives}, hashes),
    do: put_resp_header(conn, header, policy(directives, hashes))

  # Hashes go into script-src (#1). A policy without one falls back to
  # default-src in the browser, so script-src is written as default-src's
  # value plus the hashes, beside it. A policy with neither restricts no
  # script: a script-src of hashes alone would forbid every other script, so
  # none is invented.
  defp add_hashes(directives, []), do: directives

  defp add_hashes(directives, hashes) do
    cond do
      Keyword.has_key?(directives, :script_src) ->
        Keyword.update!(directives, :script_src, &Enum.join([&1 | hashes], " "))

      Keyword.has_key?(directives, :default_src) ->
        {before, [{:default_src, value} = default | rest]} =
          Enum.split_while(directives, fn {k, _} -> k != :default_src end)

        before ++ [default, {:script_src, Enum.join([value | hashes], " ")} | rest]

      true ->
        directives
    end
  end

  # Overrides replace an entry where it stands, so the header keeps one
  # order whatever is changed; new entries follow the defaults, and `nil`
  # removes one.
  defp merge_in_place(defaults, overrides) do
    (Enum.map(defaults, fn {k, v} -> {k, Keyword.get(overrides, k, v)} end) ++
       Enum.reject(overrides, fn {k, _} -> Keyword.has_key?(defaults, k) end))
    |> Enum.reject(fn {_k, v} -> v == nil end)
  end

  defp put_headers(conn, headers) do
    Enum.reduce(headers, conn, fn
      {name, nil}, conn -> delete_resp_header(conn, name)
      {name, value}, conn -> put_resp_header(conn, name, value)
    end)
  end

  # HSTS is one of the headers (#69): over https it starts from `hsts:`, and
  # `headers:` replaces or removes it like any other. Over http it is never
  # sent, since browsers ignore it there.
  defp headers(%Plug.Conn{scheme: :https}, %{headers: headers, hsts: hsts}) when is_binary(hsts),
    do: Map.merge(%{"strict-transport-security" => hsts}, headers)

  defp headers(%Plug.Conn{scheme: :https}, %{headers: headers}), do: headers

  defp headers(_conn, %{headers: headers}),
    do: Map.put(headers, "strict-transport-security", nil)
end
