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
  """

  @behaviour Plug

  import Plug.Conn

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

  @headers %{
    "x-content-type-options" => "nosniff",
    "referrer-policy" => "strict-origin-when-cross-origin",
    "x-frame-options" => "DENY",
    "cross-origin-opener-policy" => "same-origin",
    "permissions-policy" => "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
  }

  @hsts "max-age=31536000"

  @impl true
  def init(opts) do
    csp = Keyword.get(opts, :csp, [])

    Enum.each(csp, fn
      {k, v} when is_atom(k) and is_binary(v) -> :ok
      other -> raise ArgumentError, "csp: #{inspect(other)} is not {directive, value}"
    end)

    %{
      directives: merge_in_place(@directives, csp),
      headers: Map.merge(@headers, Keyword.get(opts, :headers, %{})),
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
      |> put_resp_header(
        "content-security-policy",
        policy(config.directives, conn.private.macaw_plug_script_hashes)
      )
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
    |> Enum.map_join("; ", fn {k, v} ->
      "#{k |> Atom.to_string() |> String.replace("_", "-")} #{v}"
    end)
  end

  # Without hashes the directives render as given: a script-src they lack is
  # not invented (an empty one would forbid every script).
  defp add_hashes(directives, []), do: directives

  defp add_hashes(directives, hashes),
    do:
      Keyword.update(
        directives,
        :script_src,
        Enum.join(hashes, " "),
        &Enum.join([&1 | hashes], " ")
      )

  # Overrides replace a directive where it stands, so the policy keeps one
  # order whatever is changed; new directives follow the defaults.
  defp merge_in_place(defaults, overrides) do
    Enum.map(defaults, fn {k, v} -> {k, Keyword.get(overrides, k, v)} end) ++
      Enum.reject(overrides, fn {k, _} -> Keyword.has_key?(defaults, k) end)
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
