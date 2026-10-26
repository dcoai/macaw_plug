defmodule Macaw.Plug.RateLimit do
  @moduledoc """
  Rate limiting by a generic cell rate algorithm (GCRA), in ETS.

  Each key has one *theoretical arrival time* (TAT), advanced by one emission
  interval per request with compare-and-swap, so concurrent requests on one
  key can never both take the last slot. A limiter allows `count` requests
  per `period` on average, and bursts of up to `burst`.

  Start the table once, in the host's supervision tree:

      children = [Macaw.Plug.RateLimit.Table, ...]

  Then limit with the plug, keyed by the client's address (after
  `Macaw.Plug.ClientIp`) unless told otherwise:

      plug Macaw.Plug.RateLimit, id: :api, rate: {50, :second}, burst: 200

  or call `check/3` directly. Over the limit, the plug answers `429` with a
  `Retry-After` header and halts; `:on_limit`, a `{module, function}` taking
  the conn and the seconds to wait, answers instead (a JSON API's error
  shape, say).

  Limiters share one table, each key stored as `{id, key}`. Keys idle long
  enough to have a full burst again are the same as absent, and the table's
  sweep removes them, so memory follows the active keys, not every key ever
  seen.
  """

  @behaviour Plug

  import Plug.Conn

  alias __MODULE__.Table

  @periods %{second: 1_000_000, minute: 60_000_000, hour: 3_600_000_000}

  defstruct [:id, :interval, :tolerance]

  @type t :: %__MODULE__{id: term(), interval: pos_integer(), tolerance: non_neg_integer()}

  @doc """
  A limiter: `id` names it, `rate: {count, :second | :minute | :hour}` is its
  average, and `burst` (default `count`) the most requests it takes at once.
  Raises on a rate it can't honor, naming it.
  """
  @spec new(term(), keyword()) :: t()
  def new(id, opts) do
    {count, period} = Keyword.fetch!(opts, :rate)
    burst = Keyword.get(opts, :burst, count)

    unless is_integer(count) and count > 0 and Map.has_key?(@periods, period),
      do:
        raise(
          ArgumentError,
          "rate: #{inspect({count, period})} is not {count, :second | :minute | :hour}"
        )

    unless is_integer(burst) and burst > 0,
      do: raise(ArgumentError, "burst: #{inspect(burst)} is not a positive integer")

    interval = max(1, div(@periods[period], count))
    %__MODULE__{id: id, interval: interval, tolerance: (burst - 1) * interval}
  end

  @doc """
  Takes a slot for `key` at `now` (monotonic microseconds, default the
  clock): `:ok`, or `{:error, seconds_to_wait}`, at least 1.
  """
  @spec check(t(), term(), integer()) :: :ok | {:error, pos_integer()}
  def check(%__MODULE__{} = limiter, key, now \\ System.monotonic_time(:microsecond)) do
    row_key = {limiter.id, key}

    case :ets.lookup(Table, row_key) do
      [] ->
        if :ets.insert_new(Table, {row_key, now + limiter.interval}),
          do: :ok,
          else: check(limiter, key, now)

      [{^row_key, stored} = old] ->
        tat = max(stored, now)

        if tat - now > limiter.tolerance do
          {:error, max(1, div(tat - now - limiter.tolerance + 999_999, 1_000_000))}
        else
          match = [{old, [], [{:const, {row_key, tat + limiter.interval}}]}]

          if :ets.select_replace(Table, match) == 1,
            do: :ok,
            else: check(limiter, key, now)
        end
    end
  end

  @impl true
  # Plug may run init/1 at compile time and embed its result, so the clock
  # is resolved in call/2; a test may pass `now: fun`.
  def init(opts) do
    %{
      limiter: new(Keyword.fetch!(opts, :id), opts),
      key: Keyword.get(opts, :key, :client_ip),
      on_limit: Keyword.get(opts, :on_limit),
      now: Keyword.get(opts, :now, :monotonic)
    }
  end

  @impl true
  def call(conn, %{limiter: limiter} = opts) do
    case check(limiter, key(conn, opts.key), clock(opts.now)) do
      :ok -> conn
      {:error, wait} -> limited(conn, wait, opts.on_limit)
    end
  end

  defp key(conn, :client_ip), do: conn.remote_ip
  defp key(conn, {m, f}), do: apply(m, f, [conn])

  defp clock(:monotonic), do: System.monotonic_time(:microsecond)
  defp clock(now) when is_function(now, 0), do: now.()

  defp limited(conn, wait, nil) do
    conn
    |> put_resp_header("retry-after", Integer.to_string(wait))
    |> put_resp_content_type("text/plain")
    |> send_resp(429, "Too many requests; retry in #{wait} s.\n")
    |> halt()
  end

  defp limited(conn, wait, {m, f}) do
    conn
    |> put_resp_header("retry-after", Integer.to_string(wait))
    |> then(&apply(m, f, [&1, wait]))
    |> halt()
  end
end
