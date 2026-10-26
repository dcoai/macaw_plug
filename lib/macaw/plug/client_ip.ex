defmodule Macaw.Plug.ClientIp do
  @moduledoc """
  The client's address behind trusted proxies.

  When the connection's peer is a trusted proxy, the client is the right-most
  `X-Forwarded-For` entry that is not itself a trusted proxy; entries to its
  left could have been written by the client. Otherwise the client is the
  peer, and the header is ignored. The plug sets `conn.remote_ip` to the
  client, so logging, rate limits and everything downstream key on the right
  address, and keeps the socket peer in `conn.private.macaw_plug_peer`.

      plug Macaw.Plug.ClientIp, trusted_proxies: ["10.0.0.0/8", "fd00::/8"]

  **Trusted proxies default to none.** With none trusted, every client is its
  peer: behind a reverse proxy that means every visitor looks like the
  proxy, which is wrong but never spoofable. The `:trusted_proxies` option
  takes CIDRs or single addresses, or `{module, function, args}` returning
  them, called on every request, for a list that changes at runtime. A
  malformed entry raises at `init/1`, naming it.

  **A forwarded request from an untrusted peer** (it sent `X-Forwarded-For`,
  but its address isn't trusted) is served as usual, with the header
  ignored, and emits the telemetry event
  `[:macaw_plug, :client_ip, :untrusted_forward]` with the peer in its
  metadata. It usually means a proxy in front of the app is missing from
  the trusted list. `attach_default_logger/1` logs it at most once per
  interval.
  """

  @behaviour Plug

  require Logger

  alias Macaw.Plug.Ip

  @event [:macaw_plug, :client_ip, :untrusted_forward]

  @impl true
  def init(opts) do
    case Keyword.get(opts, :trusted_proxies, []) do
      {m, f, a} when is_atom(m) and is_atom(f) and is_list(a) -> {:dynamic, {m, f, a}}
      list when is_list(list) -> {:static, cidrs!(list)}
    end
  end

  @impl true
  def call(conn, {:static, trusted}), do: put_client(conn, trusted)

  def call(conn, {:dynamic, {m, f, a}}), do: put_client(conn, cidrs!(apply(m, f, a)))

  @doc """
  The client address for a peer, its `X-Forwarded-For` entries (left to
  right, as sent) and the trusted CIDRs.
  """
  @spec resolve(Ip.ip(), [String.t()], [Ip.cidr()]) :: Ip.ip()
  def resolve(peer, forwarded, trusted) do
    peer = Ip.normalize(peer)

    if Ip.in_any?(peer, trusted) do
      forwarded
      |> Enum.reverse()
      |> Enum.map(&Ip.parse/1)
      |> Enum.reduce_while(peer, fn
        nil, _acc -> {:halt, peer}
        ip, _acc -> if Ip.in_any?(ip, trusted), do: {:cont, ip}, else: {:halt, ip}
      end)
    else
      peer
    end
  end

  @doc "The `X-Forwarded-For` entries of a request, left to right."
  @spec forwarded_for(Plug.Conn.t()) :: [String.t()]
  def forwarded_for(conn) do
    conn
    |> Plug.Conn.get_req_header("x-forwarded-for")
    |> Enum.flat_map(&String.split(&1, ","))
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  @doc "The socket peer of a request this plug has run on, else its `remote_ip`."
  @spec peer(Plug.Conn.t()) :: Ip.ip()
  def peer(conn), do: Map.get(conn.private, :macaw_plug_peer, conn.remote_ip)

  @doc """
  Logs an untrusted forward at most once per `interval_ms` (default one
  minute) on this node. Returns the telemetry handler's attach result.
  """
  @spec attach_default_logger(pos_integer()) :: :ok | {:error, :already_exists}
  def attach_default_logger(interval_ms \\ 60_000) do
    # The monotonic clock can be negative, so "never logged" is an interval
    # before now, not a fixed sentinel.
    last = :atomics.new(1, signed: true)
    :atomics.put(last, 1, System.monotonic_time(:millisecond) - interval_ms)

    :telemetry.attach(
      "macaw-plug-client-ip-logger",
      @event,
      &__MODULE__.log_untrusted/4,
      %{last: last, interval: interval_ms}
    )
  end

  @doc false
  def log_untrusted(_event, _measurements, %{peer: peer}, %{last: last, interval: interval}) do
    now = System.monotonic_time(:millisecond)
    before = :atomics.get(last, 1)

    if now - before >= interval and :atomics.compare_exchange(last, 1, before, now) == :ok do
      Logger.warning(
        "X-Forwarded-For from untrusted peer #{Ip.to_string(peer)}; " <>
          "if it is your proxy, add it to trusted_proxies"
      )
    end

    :ok
  end

  defp put_client(conn, trusted) do
    peer = Ip.normalize(conn.remote_ip)
    forwarded = forwarded_for(conn)

    if forwarded != [] and not Ip.in_any?(peer, trusted),
      do: :telemetry.execute(@event, %{count: 1}, %{peer: peer})

    %{conn | remote_ip: resolve(peer, forwarded, trusted)}
    |> Plug.Conn.put_private(:macaw_plug_peer, peer)
  end

  defp cidrs!(list) do
    Enum.map(list, fn
      {ip, prefix} = cidr when is_tuple(ip) and is_integer(prefix) ->
        cidr

      text when is_binary(text) ->
        case Ip.parse_cidr(text) do
          {:ok, cidr} -> cidr
          {:error, reason} -> raise ArgumentError, "trusted_proxies: #{reason}"
        end

      other ->
        raise ArgumentError, "trusted_proxies: #{inspect(other)} is not an address or a CIDR"
    end)
  end
end
