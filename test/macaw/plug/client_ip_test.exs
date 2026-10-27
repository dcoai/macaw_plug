defmodule Macaw.Plug.ClientIpTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Plug.Test

  alias Macaw.Plug.{ClientIp, Ip}

  @proxies ["10.0.0.0/8", "fd00::/8"]

  defp call(peer, xff, opts \\ [trusted_proxies: @proxies]) do
    conn = conn(:get, "/")
    conn = %{conn | remote_ip: peer}
    conn = if xff, do: Plug.Conn.put_req_header(conn, "x-forwarded-for", xff), else: conn
    ClientIp.call(conn, ClientIp.init(opts))
  end

  describe "addresses" do
    @tag verifies: "plug-ip"
    test "a CIDR's prefix is in 0..32 for IPv4 and 0..128 for IPv6" do
      assert Ip.parse_cidr("10.0.0.0/0") == {:ok, {{10, 0, 0, 0}, 0}}
      assert Ip.parse_cidr("10.0.0.0/32") == {:ok, {{10, 0, 0, 0}, 32}}
      assert {:error, _} = Ip.parse_cidr("10.0.0.0/33")
      assert {:error, _} = Ip.parse_cidr("10.0.0.0/-1")
      assert Ip.parse_cidr("::/0") == {:ok, {{0, 0, 0, 0, 0, 0, 0, 0}, 0}}
      assert Ip.parse_cidr("::/128") == {:ok, {{0, 0, 0, 0, 0, 0, 0, 0}, 128}}
      assert {:error, _} = Ip.parse_cidr("::/129")
    end

    @tag verifies: "ip-parse"
    test "parse/1 gives the address, trimmed and normalized, or nil" do
      assert Ip.parse("203.0.113.9") == {203, 0, 113, 9}
      assert Ip.parse(" 2001:db8::42 ") == {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x42}
      assert Ip.parse("::ffff:203.0.113.5") == {203, 0, 113, 5}
      assert Ip.parse("not-an-ip") == nil
      assert Ip.parse("10.1") == nil
      assert Ip.parse("") == nil
    end

    @tag verifies: "plug-ip-parse"
    property "parse/1 never raises on a string: it gives a normalized address or nil" do
      address_like = string(Enum.concat([?0..?9, ?a..?f, [?., ?:, ?\s, ?/]]), max_length: 24)

      check all(text <- one_of([string(:printable), address_like])) do
        ip = Ip.parse(text)
        assert ip == nil or (:inet.is_ip_address(ip) and Ip.normalize(ip) == ip)
      end
    end

    @tag verifies: "ip-parse-cidr"
    test "parse_cidr/1 gives each row of the spec's table" do
      assert Ip.parse_cidr("192.0.2.1") == {:ok, {{192, 0, 2, 1}, 32}}
      assert Ip.parse_cidr("2001:db8::1") == {:ok, {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, 128}}
      assert Ip.parse_cidr("2001:db8::/32") == {:ok, {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}}

      assert Ip.parse_cidr("10.0.0.0/40") ==
               {:error, ~s("10.0.0.0/40" has a prefix outside 0..32)}

      assert Ip.parse_cidr("10.0.0.0/x") ==
               {:error, ~s("10.0.0.0/x" has a prefix that is not a number)}

      assert Ip.parse_cidr("proxy.local") ==
               {:error, ~s("proxy.local" is not an address or a CIDR)}

      assert Ip.parse_cidr("1/2/3") == {:error, ~s("1/2/3" is not an address or a CIDR)}
    end

    @tag verifies: "plug-ip-parse-cidr"
    test "parse_cidr/1 trims, keeps the network as written, and takes only a whole decimal prefix" do
      assert Ip.parse_cidr(" 10.1.2.3/8 ") == {:ok, {{10, 1, 2, 3}, 8}}
      assert Ip.in_cidr?({10, 200, 0, 1}, {{10, 1, 2, 3}, 8})
      refute Ip.in_cidr?({11, 1, 2, 3}, {{10, 1, 2, 3}, 8})

      assert Ip.parse_cidr("10.0.0.0/8.0") ==
               {:error, ~s("10.0.0.0/8.0" has a prefix that is not a number)}

      assert Ip.parse_cidr("10.0.0.0/") ==
               {:error, ~s("10.0.0.0/" has a prefix that is not a number)}

      assert Ip.parse_cidr("2001:db8::/129") ==
               {:error, ~s("2001:db8::/129" has a prefix outside 0..128)}
    end

    @tag verifies: "ip-normalize"
    test "normalize/1 turns an IPv4-mapped address into IPv4 and returns any other unchanged" do
      assert Ip.normalize({0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0005}) == {10, 0, 0, 5}
      assert Ip.normalize({203, 0, 113, 9}) == {203, 0, 113, 9}

      assert Ip.normalize({0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x42}) ==
               {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x42}
    end

    @tag verifies: "ip-membership"
    test "an address is in a CIDR of its own family; in_any?/2 normalizes first" do
      assert Ip.in_cidr?({10, 9, 9, 9}, {{10, 0, 0, 0}, 8})
      refute Ip.in_cidr?({10, 9, 9, 9}, {{11, 0, 0, 0}, 8})
      refute Ip.in_cidr?({10, 9, 9, 9}, {{0, 0, 0, 0, 0, 0, 0, 0}, 0})
      assert Ip.in_any?({0, 0, 0, 0, 0, 0xFFFF, 0x0A09, 0x0909}, [{{10, 0, 0, 0}, 8}])
      refute Ip.in_any?({10, 9, 9, 9}, [])
    end

    @tag verifies: "plug-ip-membership"
    property "the first prefix bits decide; a /0 holds its whole family and no other" do
      assert Ip.in_cidr?({10, 127, 255, 255}, {{10, 0, 0, 0}, 9})
      refute Ip.in_cidr?({10, 128, 0, 0}, {{10, 0, 0, 0}, 9})
      assert Ip.in_any?({10, 1, 1, 1}, [{{11, 0, 0, 0}, 8}, {{10, 0, 0, 0}, 8}])

      check all(ip <- ip4(), ip6 <- ip6()) do
        assert Ip.in_cidr?(ip, {{255, 255, 255, 255}, 0})
        refute Ip.in_cidr?(ip, {{0, 0, 0, 0, 0, 0, 0, 0}, 0})
        assert Ip.in_cidr?(ip6, {{0xFFFF, 0, 0, 0, 0, 0, 0, 0}, 0})
        refute Ip.in_cidr?(ip6, {{0, 0, 0, 0}, 0})
      end
    end

    @tag verifies: "plug-ip-to-string"
    test "to_string/1 formats as :inet.ntoa/1 does" do
      assert Ip.to_string({203, 0, 113, 9}) == "203.0.113.9"
      assert Ip.to_string({0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x42}) == "2001:db8::42"
    end

    @tag verifies: "ip-to-string"
    property "to_string/1 then parse/1 gives the address back" do
      check all(
              ip <- one_of([ip4(), ip6()]),
              not match?({0, 0, 0, 0, 0, 0xFFFF, _, _}, ip)
            ) do
        assert ip |> Ip.to_string() |> Ip.parse() == ip
      end
    end
  end

  describe "trusted peer" do
    @tag verifies: "plug-client-ip-rule"
    test "the right-most untrusted entry is the client" do
      conn = call({10, 0, 0, 5}, "198.51.100.7, 203.0.113.9, 10.1.2.3")
      assert conn.remote_ip == {203, 0, 113, 9}
      assert ClientIp.peer(conn) == {10, 0, 0, 5}
    end

    @tag verifies: "plug-client-ip-rule"
    test "entries to the left of the first untrusted one are ignored, since a client can forge them" do
      conn = call({10, 0, 0, 5}, "1.1.1.1, 203.0.113.9")
      assert conn.remote_ip == {203, 0, 113, 9}
    end

    @tag verifies: "client-ip-several-headers"
    test "several headers are read in order; empty entries are dropped" do
      conn =
        conn(:get, "/")
        |> Map.put(:remote_ip, {10, 0, 0, 5})
        |> Map.update!(:req_headers, fn h ->
          h ++ [{"x-forwarded-for", "198.51.100.7"}, {"x-forwarded-for", "203.0.113.9"}]
        end)
        |> ClientIp.call(ClientIp.init(trusted_proxies: @proxies))

      assert conn.remote_ip == {203, 0, 113, 9}

      forwarded = conn(:get, "/") |> Plug.Conn.put_req_header("x-forwarded-for", "a, ,b")
      assert ClientIp.forwarded_for(forwarded) == ["a", "b"]
    end

    @tag verifies: "plug-client-ip-forwarded"
    test "forwarded_for/1: every header in order, split on commas, trimmed, empties dropped" do
      conn =
        conn(:get, "/")
        |> Map.update!(:req_headers, fn h ->
          h ++ [{"x-forwarded-for", " a ,b,"}, {"x-forwarded-for", ", c"}]
        end)

      assert ClientIp.forwarded_for(conn) == ["a", "b", "c"]
      assert ClientIp.forwarded_for(conn(:get, "/")) == []
    end

    @tag verifies: "plug-client-ip-rule"
    test "a malformed entry stops the walk at the peer" do
      assert call({10, 0, 0, 5}, "203.0.113.9, not-an-ip").remote_ip == {10, 0, 0, 5}
    end

    @tag verifies: "plug-client-ip-rule"
    test "all entries trusted gives the left-most trusted one" do
      assert call({10, 0, 0, 5}, "10.9.9.9, 10.1.1.1").remote_ip == {10, 9, 9, 9}
    end

    @tag verifies: "plug-client-ip-rule"
    test "IPv6 proxies and clients" do
      conn = call({0xFD00, 0, 0, 0, 0, 0, 0, 1}, "2001:db8::42")
      assert conn.remote_ip == {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x42}
    end

    @tag verifies: "plug-ip-normalize"
    test "an IPv4-mapped peer matches an IPv4 trusted proxy" do
      mapped = {0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0005}
      assert call(mapped, "203.0.113.9").remote_ip == {203, 0, 113, 9}
    end

    @tag verifies: "plug-client-ip-rule"
    test "resolve/3: no entries give the peer; peer, entries and client are compared normalized" do
      trusted = cidrs()
      mapped_peer = {0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0005}

      assert ClientIp.resolve({10, 0, 0, 5}, [], trusted) == {10, 0, 0, 5}
      assert ClientIp.resolve(mapped_peer, [], trusted) == {10, 0, 0, 5}

      assert ClientIp.resolve({10, 0, 0, 5}, ["203.0.113.9", "::ffff:10.1.1.1"], trusted) ==
               {203, 0, 113, 9}

      assert ClientIp.resolve({10, 0, 0, 5}, ["::ffff:203.0.113.9"], trusted) ==
               {203, 0, 113, 9}
    end
  end

  describe "the spec's table" do
    @rows [
      {{10, 0, 0, 5}, "198.51.100.7, 203.0.113.9, 10.1.2.3", {203, 0, 113, 9}},
      {{10, 0, 0, 5}, "1.1.1.1, 203.0.113.9", {203, 0, 113, 9}},
      {{10, 0, 0, 5}, "203.0.113.9, not-an-ip", {10, 0, 0, 5}},
      {{10, 0, 0, 5}, "10.9.9.9, 10.1.1.1", {10, 9, 9, 9}},
      {{198, 51, 100, 7}, "203.0.113.9", {198, 51, 100, 7}},
      {{0xFD00, 0, 0, 0, 0, 0, 0, 1}, "2001:db8::42", {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x42}},
      {{0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0005}, "203.0.113.9", {203, 0, 113, 9}}
    ]

    @tag verifies: "client-ip-rows"
    test "each row, with 10.0.0.0/8 and fd00::/8 trusted" do
      for {peer, xff, client} <- @rows do
        assert {peer, xff, call(peer, xff).remote_ip} == {peer, xff, client}
      end
    end
  end

  describe "untrusted peer" do
    @tag verifies: "plug-client-ip-rule"
    test "the header is ignored" do
      assert call({198, 51, 100, 7}, "203.0.113.9").remote_ip == {198, 51, 100, 7}
    end

    @tag verifies: "client-ip-default-none"
    test "trusting nothing is the default" do
      assert call({10, 0, 0, 5}, "203.0.113.9", []).remote_ip == {10, 0, 0, 5}
    end

    @tag verifies: "client-ip-event"
    test "a forwarded request emits the untrusted-forward event; one without the header does not" do
      ref =
        :telemetry_test.attach_event_handlers(self(), [
          [:macaw_plug, :client_ip, :untrusted_forward]
        ])

      call({198, 51, 100, 7}, "203.0.113.9")

      assert_receive {[:macaw_plug, :client_ip, :untrusted_forward], ^ref, %{count: 1},
                      %{peer: {198, 51, 100, 7}}}

      call({198, 51, 100, 8}, nil)
      refute_receive {_, ^ref, _, %{peer: {198, 51, 100, 8}}}
    end

    @tag verifies: "plug-client-ip-event"
    test "only a non-empty header from an untrusted peer emits, with the peer normalized" do
      ref =
        :telemetry_test.attach_event_handlers(self(), [
          [:macaw_plug, :client_ip, :untrusted_forward]
        ])

      # empty entries only, then a trusted peer forwarding, then a mapped untrusted peer
      call({198, 51, 100, 9}, " , ")
      call({10, 0, 0, 5}, "203.0.113.9")
      conn = call({0, 0, 0, 0, 0, 0xFFFF, 0xC633, 0x640A}, "203.0.113.9")

      assert conn.remote_ip == {198, 51, 100, 10}

      assert_receive {[:macaw_plug, :client_ip, :untrusted_forward], ^ref, %{count: 1},
                      %{peer: {198, 51, 100, 10}}}

      refute_received {_, ^ref, _, _}
    end
  end

  describe "what the plug sets" do
    @tag verifies: "client-ip-peer"
    test "remote_ip is the client and peer/1 the socket peer; without the plug, peer/1 is remote_ip" do
      conn = call({10, 0, 0, 5}, "203.0.113.9")
      assert conn.remote_ip == {203, 0, 113, 9}
      assert ClientIp.peer(conn) == {10, 0, 0, 5}

      assert ClientIp.peer(%{conn(:get, "/") | remote_ip: {192, 0, 2, 1}}) == {192, 0, 2, 1}
    end

    @tag verifies: "plug-client-ip-call"
    test "the client is written in remote_ip only; the peer, normalized, in private" do
      ref =
        :telemetry_test.attach_event_handlers(self(), [
          [:macaw_plug, :client_ip, :untrusted_forward]
        ])

      conn = call({0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0005}, "203.0.113.9")
      assert conn.remote_ip == {203, 0, 113, 9}
      assert conn.private.macaw_plug_peer == {10, 0, 0, 5}
      assert conn.assigns == %{}

      call({198, 51, 100, 7}, "203.0.113.9")
      assert_receive {_, ^ref, %{count: 1}, %{peer: {198, 51, 100, 7}}}
    end
  end

  describe "configuration" do
    @tag verifies: "client-ip-init-raises"
    test "a malformed entry raises at init, naming it" do
      assert_raise ArgumentError, ~r/"10.0.0.0\/40" has a prefix outside/, fn ->
        ClientIp.init(trusted_proxies: ["10.0.0.0/40"])
      end

      assert_raise ArgumentError, ~r/"proxy.local" is not an address/, fn ->
        ClientIp.init(trusted_proxies: ["proxy.local"])
      end
    end

    @tag verifies: "plug-client-ip-config"
    test "a list takes {address, prefix} tuples as they are; any other entry raises at init, or is dropped from a dynamic list" do
      static = [trusted_proxies: [{{10, 0, 0, 0}, 8}]]
      assert call({10, 0, 0, 5}, "203.0.113.9", static).remote_ip == {203, 0, 113, 9}

      assert_raise ArgumentError,
                   ~s(trusted_proxies: "10.0.0.0/40" has a prefix outside 0..32),
                   fn ->
                     ClientIp.init(trusted_proxies: ["10.0.0.0/40"])
                   end

      assert_raise ArgumentError, "trusted_proxies: 42 is not an address or a CIDR", fn ->
        ClientIp.init(trusted_proxies: [42])
      end

      ref =
        :telemetry_test.attach_event_handlers(self(), [
          [:macaw_plug, :client_ip, :bad_proxy_entry]
        ])

      :persistent_term.put({__MODULE__, :proxies}, [{{10, 0, 0, 0}, 8}, 42])
      dynamic = [trusted_proxies: {__MODULE__, :proxies, []}]
      assert call({10, 0, 0, 5}, "203.0.113.9", dynamic).remote_ip == {203, 0, 113, 9}

      assert_receive {[:macaw_plug, :client_ip, :bad_proxy_entry], ^ref, %{count: 1},
                      %{entry: 42, reason: "42 is not an address or a CIDR"}}
    end

    @tag verifies: "client-ip-dynamic"
    test "a dynamic list is read on every request" do
      :persistent_term.put({__MODULE__, :proxies}, ["10.0.0.0/8"])
      opts = [trusted_proxies: {__MODULE__, :proxies, []}]
      assert call({10, 0, 0, 5}, "203.0.113.9", opts).remote_ip == {203, 0, 113, 9}

      :persistent_term.put({__MODULE__, :proxies}, [])
      assert call({10, 0, 0, 5}, "203.0.113.9", opts).remote_ip == {10, 0, 0, 5}
    end
  end

  describe "a dynamic list with a bad entry (#69)" do
    @tag verifies: "client-ip-dynamic-bad-entry"
    test "the bad entry is dropped and reported; the request is served" do
      ref =
        :telemetry_test.attach_event_handlers(self(), [
          [:macaw_plug, :client_ip, :bad_proxy_entry]
        ])

      :persistent_term.put({__MODULE__, :proxies}, ["10.0.0.0/8", "not-a-cidr"])
      opts = [trusted_proxies: {__MODULE__, :proxies, []}]

      assert call({10, 0, 0, 5}, "203.0.113.9", opts).remote_ip == {203, 0, 113, 9}

      assert_receive {[:macaw_plug, :client_ip, :bad_proxy_entry], ^ref, %{count: 1},
                      %{entry: "not-a-cidr"}}
    end
  end

  def proxies, do: :persistent_term.get({__MODULE__, :proxies})

  describe "the default logger" do
    import ExUnit.CaptureLog

    @tag verifies: "client-ip-logger-once"
    test "logs at most once per interval" do
      :telemetry.detach("macaw-plug-client-ip-logger")
      :ok = ClientIp.attach_default_logger(60_000)
      on_exit(fn -> :telemetry.detach("macaw-plug-client-ip-logger") end)

      log =
        capture_log(fn ->
          call({198, 51, 100, 7}, "203.0.113.9")
          call({198, 51, 100, 7}, "203.0.113.9")
        end)

      assert length(Regex.scan(~r/untrusted peer 198\.51\.100\.7/, log)) == 1
    end

    @tag verifies: "plug-client-ip-logger"
    test "each event logs its own message once per interval, concurrent events once; a second attach is refused" do
      :telemetry.detach("macaw-plug-client-ip-logger")
      # the default interval, one minute
      assert ClientIp.attach_default_logger() == :ok
      on_exit(fn -> :telemetry.detach("macaw-plug-client-ip-logger") end)
      assert ClientIp.attach_default_logger(60_000) == {:error, :already_exists}

      :persistent_term.put({__MODULE__, :proxies}, ["10.0.0.0/8", "not-a-cidr"])
      dynamic = [trusted_proxies: {__MODULE__, :proxies, []}]

      log =
        capture_log(fn ->
          1..50
          |> Task.async_stream(fn _ -> call({198, 51, 100, 7}, "203.0.113.9") end,
            max_concurrency: 50
          )
          |> Stream.run()

          call({10, 0, 0, 5}, "203.0.113.9", dynamic)
          call({10, 0, 0, 5}, "203.0.113.9", dynamic)
        end)

      untrusted =
        "X-Forwarded-For from untrusted peer 198.51.100.7; " <>
          "if it is your proxy, add it to trusted_proxies"

      bad =
        ~s{trusted_proxies: ignored "not-a-cidr" ("not-a-cidr" is not an address or a CIDR); } <>
          "fix the list it came from"

      assert length(String.split(log, untrusted)) == 2
      assert length(String.split(log, bad)) == 2
    end
  end

  @tag verifies: "client-ip-never-proxy"
  property "the client is never a trusted proxy unless every hop is" do
    check all(hops <- list_of(ip4(), max_length: 6), peer <- trusted_ip4()) do
      conn = call(peer, Enum.map_join(hops, ", ", &Ip.to_string/1))
      untrusted = Enum.reject(hops, &Ip.in_any?(&1, cidrs()))

      case untrusted do
        [] -> assert Ip.in_any?(conn.remote_ip, cidrs())
        _ -> assert conn.remote_ip == List.last(untrusted)
      end
    end
  end

  @tag verifies: "client-ip-untrusted-own"
  property "an untrusted peer is always its own client, whatever it sends" do
    check all(peer <- ip4(), not Ip.in_any?(peer, cidrs()), hops <- list_of(ip4(), max_length: 4)) do
      assert call(peer, Enum.map_join(hops, ", ", &Ip.to_string/1)).remote_ip == peer
    end
  end

  defp cidrs, do: Enum.map(@proxies, fn c -> elem(Ip.parse_cidr(c), 1) end)
  defp ip4, do: tuple({integer(0..255), integer(0..255), integer(0..255), integer(0..255)})
  defp trusted_ip4, do: tuple({constant(10), integer(0..255), integer(0..255), integer(1..254)})
  defp ip6, do: tuple(List.to_tuple(List.duplicate(integer(0..0xFFFF), 8)))
end
