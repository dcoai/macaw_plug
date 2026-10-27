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

  describe "trusted peer" do
    test "the right-most untrusted entry is the client" do
      conn = call({10, 0, 0, 5}, "198.51.100.7, 203.0.113.9, 10.1.2.3")
      assert conn.remote_ip == {203, 0, 113, 9}
      assert ClientIp.peer(conn) == {10, 0, 0, 5}
    end

    test "entries to the left of the first untrusted one are ignored, since a client can forge them" do
      conn = call({10, 0, 0, 5}, "1.1.1.1, 203.0.113.9")
      assert conn.remote_ip == {203, 0, 113, 9}
    end

    test "several headers are read in order" do
      conn =
        conn(:get, "/")
        |> Map.put(:remote_ip, {10, 0, 0, 5})
        |> Map.update!(:req_headers, fn h ->
          h ++ [{"x-forwarded-for", "198.51.100.7"}, {"x-forwarded-for", "203.0.113.9"}]
        end)
        |> ClientIp.call(ClientIp.init(trusted_proxies: @proxies))

      assert conn.remote_ip == {203, 0, 113, 9}
    end

    test "a malformed entry stops the walk at the peer" do
      assert call({10, 0, 0, 5}, "203.0.113.9, not-an-ip").remote_ip == {10, 0, 0, 5}
    end

    test "all entries trusted gives the left-most trusted one" do
      assert call({10, 0, 0, 5}, "10.9.9.9, 10.1.1.1").remote_ip == {10, 9, 9, 9}
    end

    test "IPv6 proxies and clients" do
      conn = call({0xFD00, 0, 0, 0, 0, 0, 0, 1}, "2001:db8::42")
      assert conn.remote_ip == {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x42}
    end

    test "an IPv4-mapped peer matches an IPv4 trusted proxy" do
      mapped = {0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0005}
      assert call(mapped, "203.0.113.9").remote_ip == {203, 0, 113, 9}
    end
  end

  describe "untrusted peer" do
    test "the header is ignored" do
      assert call({198, 51, 100, 7}, "203.0.113.9").remote_ip == {198, 51, 100, 7}
    end

    test "trusting nothing is the default" do
      assert call({10, 0, 0, 5}, "203.0.113.9", []).remote_ip == {10, 0, 0, 5}
    end

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
  end

  describe "configuration" do
    test "a single address is a /32" do
      assert Ip.parse_cidr("192.0.2.1") == {:ok, {{192, 0, 2, 1}, 32}}
    end

    test "a malformed entry raises at init, naming it" do
      assert_raise ArgumentError, ~r/"10.0.0.0\/40" has a prefix outside/, fn ->
        ClientIp.init(trusted_proxies: ["10.0.0.0/40"])
      end

      assert_raise ArgumentError, ~r/"proxy.local" is not an address/, fn ->
        ClientIp.init(trusted_proxies: ["proxy.local"])
      end
    end

    test "a dynamic list is read on every request" do
      :persistent_term.put({__MODULE__, :proxies}, ["10.0.0.0/8"])
      opts = [trusted_proxies: {__MODULE__, :proxies, []}]
      assert call({10, 0, 0, 5}, "203.0.113.9", opts).remote_ip == {203, 0, 113, 9}

      :persistent_term.put({__MODULE__, :proxies}, [])
      assert call({10, 0, 0, 5}, "203.0.113.9", opts).remote_ip == {10, 0, 0, 5}
    end
  end

  describe "a dynamic list with a bad entry (#69)" do
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
  end

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

  property "an untrusted peer is always its own client, whatever it sends" do
    check all(peer <- ip4(), not Ip.in_any?(peer, cidrs()), hops <- list_of(ip4(), max_length: 4)) do
      assert call(peer, Enum.map_join(hops, ", ", &Ip.to_string/1)).remote_ip == peer
    end
  end

  defp cidrs, do: Enum.map(@proxies, fn c -> elem(Ip.parse_cidr(c), 1) end)
  defp ip4, do: tuple({integer(0..255), integer(0..255), integer(0..255), integer(0..255)})
  defp trusted_ip4, do: tuple({constant(10), integer(0..255), integer(0..255), integer(1..254)})
end
