defmodule Macaw.Plug.SecurityHeadersTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias Macaw.Plug.SecurityHeaders

  @closed "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " <>
            "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; " <>
            "form-action 'self'; frame-ancestors 'none'"

  @standard [
    "x-content-type-options",
    "referrer-policy",
    "x-frame-options",
    "cross-origin-opener-policy",
    "permissions-policy"
  ]

  defp run(opts \\ [], fun \\ & &1, scheme \\ :http) do
    conn(:get, "/")
    |> Map.put(:scheme, scheme)
    |> SecurityHeaders.call(SecurityHeaders.init(opts))
    |> fun.()
    |> send_resp(200, "ok")
  end

  defp header(conn, name), do: conn |> get_resp_header(name) |> List.first()

  @tag verifies: "headers-default-policy"
  test "the default policy is closed" do
    assert header(run(), "content-security-policy") ==
             "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " <>
               "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; " <>
               "form-action 'self'; frame-ancestors 'none'"

    refute header(run(), "content-security-policy") =~ "unsafe"
  end

  @tag verifies: "plug-headers-policy"
  test "policy/2 renders directives in order, as name and value, joined by \"; \"" do
    assert SecurityHeaders.policy() == @closed

    assert SecurityHeaders.policy(worker_src: "'self'", img_src: "x") ==
             "worker-src 'self'; img-src x"

    assert SecurityHeaders.policy([script_src: "'self'"], ["'sha256-a'"]) ==
             "script-src 'self' 'sha256-a'"
  end

  @tag verifies: "headers-standard"
  test "the standard headers are on every response" do
    conn = run()
    assert header(conn, "x-content-type-options") == "nosniff"
    assert header(conn, "referrer-policy") == "strict-origin-when-cross-origin"
    assert header(conn, "x-frame-options") == "DENY"
    assert header(conn, "cross-origin-opener-policy") == "same-origin"

    assert header(conn, "permissions-policy") ==
             "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
  end

  @tag verifies: "headers-every-response"
  test "every response carries the policy and the five standard headers" do
    send = [
      &send_resp(&1, 200, "ok"),
      &send_resp(&1, 302, ""),
      &send_resp(&1, 404, "not found"),
      &send_resp(&1, 500, "error"),
      &send_chunked(&1, 200),
      &send_file(&1, 200, __ENV__.file)
    ]

    for method <- [:get, :post, :delete], sent <- send do
      conn =
        conn(method, "/")
        |> SecurityHeaders.call(SecurityHeaders.init([]))
        |> sent.()

      for name <- ["content-security-policy" | @standard] do
        assert {^method, _, ^name, [_]} = {method, conn.status, name, get_resp_header(conn, name)}
      end
    end
  end

  @tag verifies: "headers-hsts"
  test "HSTS only over https" do
    assert header(run(), "strict-transport-security") == nil
    assert header(run([], & &1, :https), "strict-transport-security") == "max-age=31536000"
    assert header(run([hsts: nil], & &1, :https), "strict-transport-security") == nil
  end

  @tag verifies: "plug-headers-hsts"
  test "hsts: sets the default value or, not a string, turns it off; over http none, whatever headers: says" do
    sts = "strict-transport-security"
    assert header(run([hsts: "max-age=10"], & &1, :https), sts) == "max-age=10"
    assert header(run([hsts: false], & &1, :https), sts) == nil
    assert header(run(headers: %{sts => "max-age=60"}), sts) == nil
    assert header(run(hsts: "max-age=10"), sts) == nil
  end

  @tag verifies: "headers-override-in-place"
  test "a directive changes only by naming it" do
    policy =
      header(run(csp: [img_src: "'self' https://tiles.example"]), "content-security-policy")

    assert policy =~ "style-src 'self'; img-src 'self' https://tiles.example; font-src 'self';"
    assert policy =~ "default-src 'self';"
  end

  @tag verifies: "headers-override-added"
  test "a directive the defaults lack is added after them" do
    assert header(run(csp: [worker_src: "'self'"]), "content-security-policy") ==
             @closed <> "; worker-src 'self'"
  end

  @tag verifies: "plug-headers-overrides"
  test "overrides keep one order, tighten or loosen as named, and must be {atom, string}" do
    csp = [
      worker_src: "w",
      frame_ancestors: "'self'",
      manifest_src: "m",
      default_src: "'none'",
      script_src: "'self' 'unsafe-inline'"
    ]

    assert header(run(csp: csp), "content-security-policy") ==
             "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self'; " <>
               "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; " <>
               "base-uri 'none'; form-action 'self'; frame-ancestors 'self'; " <>
               "worker-src w; manifest-src m"

    assert_raise ArgumentError, "csp: {:img_src, nil} is not {directive, value}", fn ->
      SecurityHeaders.init(csp: [img_src: nil])
    end

    assert_raise ArgumentError, ~s(csp: {"img-src", "x"} is not {directive, value}), fn ->
      SecurityHeaders.init(csp: [{"img-src", "x"}])
    end
  end

  @tag verifies: "headers-override-raises"
  test "a malformed directive raises at init" do
    assert_raise ArgumentError, ~r/csp: "img-src"/, fn ->
      SecurityHeaders.init(csp: ["img-src"])
    end
  end

  @tag verifies: "headers-replace-remove"
  test "a header is replaced or removed by name" do
    conn = run(headers: %{"x-frame-options" => nil, "referrer-policy" => "no-referrer"})
    assert header(conn, "x-frame-options") == nil
    assert header(conn, "referrer-policy") == "no-referrer"
  end

  @tag verifies: "plug-headers-standard"
  test "headers: adds a header the table lacks, beside the standard ones" do
    conn = run(headers: %{"x-permitted-cross-domain-policies" => "none"})
    assert header(conn, "x-permitted-cross-domain-policies") == "none"
    for name <- @standard, do: assert([_] = get_resp_header(conn, name))
  end

  @tag verifies: "plug-headers-call"
  test "nothing is written until the response is sent; then each header replaces a controller's value" do
    conn = conn(:get, "/") |> SecurityHeaders.call(SecurityHeaders.init([]))

    for name <- ["content-security-policy" | @standard],
        do: assert(get_resp_header(conn, name) == [])

    conn =
      conn
      |> put_resp_header("x-frame-options", "SAMEORIGIN")
      |> put_resp_header("content-security-policy", "default-src *")
      |> send_resp(200, "ok")

    assert get_resp_header(conn, "x-frame-options") == ["DENY"]
    assert get_resp_header(conn, "content-security-policy") == [@closed]
  end

  describe "inline script hashes" do
    @tag verifies: "headers-hash-vector"
    test "the hash is SHA-256 of the exact body, base64" do
      # echo -n 'alert(1)' | openssl dgst -sha256 -binary | base64
      assert SecurityHeaders.hash("alert(1)") ==
               "'sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='"
    end

    @tag verifies: "headers-hash-once"
    test "a hash added after the plug ran reaches the policy, once" do
      conn =
        run(
          [],
          &(&1
            |> SecurityHeaders.put_script_hash("a()")
            |> SecurityHeaders.put_script_hash("a()"))
        )

      policy = header(conn, "content-security-policy")
      assert policy =~ "script-src 'self' #{SecurityHeaders.hash("a()")};"
      assert length(Regex.scan(~r/sha256-/, policy)) == 1
    end

    @tag verifies: "headers-two-hashes"
    test "two scripts, two hashes" do
      conn =
        run(
          [],
          &(&1
            |> SecurityHeaders.put_script_hash("a()")
            |> SecurityHeaders.put_script_hash("b()"))
        )

      assert header(conn, "content-security-policy") =~
               "script-src 'self' #{SecurityHeaders.hash("a()")} #{SecurityHeaders.hash("b()")};"
    end

    @tag verifies: "plug-headers-hashes"
    test "a hash is of the body byte for byte; the list keeps first-added order, after script-src's value" do
      refute SecurityHeaders.hash("a()") == SecurityHeaders.hash(" a()")
      refute SecurityHeaders.hash("a()") == SecurityHeaders.hash("a();")

      conn =
        run(
          [csp: [script_src: "'self' https://cdn.example"]],
          &(&1
            |> SecurityHeaders.put_script_hash("b()")
            |> SecurityHeaders.put_script_hash("a()")
            |> SecurityHeaders.put_script_hash("b()"))
        )

      policy = header(conn, "content-security-policy")

      assert policy =~
               "script-src 'self' https://cdn.example " <>
                 "#{SecurityHeaders.hash("b()")} #{SecurityHeaders.hash("a()")};"

      refute policy =~ "unsafe-inline"
    end
  end

  describe "gaps fixed in #69" do
    @tag verifies: "headers-hsts-via-headers"
    test "HSTS is replaced or removed through headers:, like any header" do
      conn = run([headers: %{"strict-transport-security" => nil}], & &1, :https)
      assert header(conn, "strict-transport-security") == nil

      conn = run([headers: %{"strict-transport-security" => "max-age=60"}], & &1, :https)
      assert header(conn, "strict-transport-security") == "max-age=60"
    end

    @tag verifies: "headers-hash-before-plug"
    test "a script hash added before the plug runs is kept" do
      conn =
        conn(:get, "/")
        |> SecurityHeaders.put_script_hash("early()")
        |> SecurityHeaders.call(SecurityHeaders.init([]))
        |> send_resp(200, "ok")

      assert header(conn, "content-security-policy") =~ SecurityHeaders.hash("early()")
    end
  end
end
