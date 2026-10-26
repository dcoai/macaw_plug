defmodule Macaw.Plug.SecurityHeadersTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias Macaw.Plug.SecurityHeaders

  defp run(opts \\ [], fun \\ & &1, scheme \\ :http) do
    conn(:get, "/")
    |> Map.put(:scheme, scheme)
    |> SecurityHeaders.call(SecurityHeaders.init(opts))
    |> fun.()
    |> send_resp(200, "ok")
  end

  defp header(conn, name), do: conn |> get_resp_header(name) |> List.first()

  test "the default policy is closed" do
    assert header(run(), "content-security-policy") ==
             "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " <>
               "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; " <>
               "form-action 'self'; frame-ancestors 'none'"

    refute header(run(), "content-security-policy") =~ "unsafe"
  end

  test "the standard headers are on every response" do
    conn = run()
    assert header(conn, "x-content-type-options") == "nosniff"
    assert header(conn, "referrer-policy") == "strict-origin-when-cross-origin"
    assert header(conn, "x-frame-options") == "DENY"
    assert header(conn, "cross-origin-opener-policy") == "same-origin"
    assert header(conn, "permissions-policy") =~ "camera=()"
  end

  test "HSTS only over https" do
    assert header(run(), "strict-transport-security") == nil
    assert header(run([], & &1, :https), "strict-transport-security") == "max-age=31536000"
  end

  test "a directive changes only by naming it" do
    policy =
      header(run(csp: [img_src: "'self' https://tiles.example"]), "content-security-policy")

    assert policy =~ "img-src 'self' https://tiles.example;"
    assert policy =~ "default-src 'self';"
  end

  test "a malformed directive raises at init" do
    assert_raise ArgumentError, ~r/csp: "img-src"/, fn ->
      SecurityHeaders.init(csp: ["img-src"])
    end
  end

  test "a header is replaced or removed by name" do
    conn = run(headers: %{"x-frame-options" => nil, "referrer-policy" => "no-referrer"})
    assert header(conn, "x-frame-options") == nil
    assert header(conn, "referrer-policy") == "no-referrer"
  end

  describe "inline script hashes" do
    test "the hash is SHA-256 of the exact body, base64" do
      # echo -n 'alert(1)' | openssl dgst -sha256 -binary | base64
      assert SecurityHeaders.hash("alert(1)") ==
               "'sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='"
    end

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
  end
end
