defmodule Macaw.Plug.RateLimitTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Plug.Test

  alias Macaw.Plug.RateLimit
  alias Macaw.Plug.RateLimit.Table

  @second 1_000_000

  setup_all do
    start_supervised!({Table, sweep_every: 3_600_000})
    :ok
  end

  # Each test uses its own limiter id, so async tests never share keys.
  defp limiter(opts), do: RateLimit.new(make_ref(), opts)

  @tag verifies: "plug-rate-gcra"
  test "the interval is period / count in whole µs, at least 1; a refusal costs nothing; an idle key has its burst" do
    assert %RateLimit{interval: 333_333, tolerance: 666_666} =
             RateLimit.new(:x, rate: {3, :second})

    assert %RateLimit{interval: 1, tolerance: 0} =
             RateLimit.new(:x, rate: {2_000_000, :second}, burst: 1)

    l = limiter(rate: {1, :second})

    # a key never seen is allowed, its TAT now + interval
    assert RateLimit.check(l, :k, 0) == :ok
    assert :ets.lookup(Table, {l.id, :k}) == [{{l.id, :k}, @second}]

    # refused requests leave the TAT as it was
    for _ <- 1..5, do: assert({:error, 1} = RateLimit.check(l, :k, 0))
    assert :ets.lookup(Table, {l.id, :k}) == [{{l.id, :k}, @second}]
    assert RateLimit.check(l, :k, @second) == :ok

    # after a burst, a key idle long enough has its full burst again
    b = limiter(rate: {10, :second}, burst: 3)
    for _ <- 1..3, do: assert(RateLimit.check(b, :k, 0) == :ok)
    assert {:error, _} = RateLimit.check(b, :k, 0)
    for _ <- 1..3, do: assert(RateLimit.check(b, :k, @second) == :ok)
    assert {:error, _} = RateLimit.check(b, :k, @second)
  end

  @tag verifies: "rate-burst-then-interval"
  test "a burst is allowed at once, then one per interval" do
    l = limiter(rate: {10, :second}, burst: 3)
    t = 0

    assert RateLimit.check(l, :k, t) == :ok
    assert RateLimit.check(l, :k, t) == :ok
    assert RateLimit.check(l, :k, t) == :ok
    assert {:error, 1} = RateLimit.check(l, :k, t)

    # one interval (100 ms) later, exactly one more
    assert RateLimit.check(l, :k, t + div(@second, 10)) == :ok
    assert {:error, _} = RateLimit.check(l, :k, t + div(@second, 10))
  end

  @tag verifies: "rate-keys-independent"
  test "keys are independent" do
    l = limiter(rate: {1, :minute})
    assert RateLimit.check(l, :a, 0) == :ok
    assert {:error, 60} = RateLimit.check(l, :a, 0)
    assert RateLimit.check(l, :b, 0) == :ok
  end

  @tag verifies: "rate-wait"
  test "the wait is the time until a slot frees, rounded up to a second" do
    l = limiter(rate: {1, :minute})
    assert RateLimit.check(l, :k, 0) == :ok
    assert {:error, 60} = RateLimit.check(l, :k, 0)
    assert {:error, 1} = RateLimit.check(l, :k, 59 * @second + 1)
    assert RateLimit.check(l, :k, 60 * @second) == :ok
  end

  @tag verifies: "plug-rate-check"
  test "check reads the monotonic clock by default, and rounds a wait up to a whole second" do
    l = limiter(rate: {1, :minute})
    assert RateLimit.check(l, :k) == :ok
    assert {:error, 60} = RateLimit.check(l, :k)

    l = limiter(rate: {1, :minute})
    assert RateLimit.check(l, :k, 0) == :ok
    assert {:error, 31} = RateLimit.check(l, :k, 30 * @second - 1)
    assert {:error, 30} = RateLimit.check(l, :k, 30 * @second + div(@second, 2))
  end

  @tag verifies: "plug-rate-new"
  test "a limiter: named by any term, never sharing a key with another; rate required; burst count by default" do
    id = make_ref()
    a = RateLimit.new({id, "a"}, rate: {1, :minute})
    b = RateLimit.new({id, "b"}, rate: {1, :minute})
    assert RateLimit.check(a, :k, 0) == :ok
    assert RateLimit.check(b, :k, 0) == :ok
    assert {:error, 60} = RateLimit.check(a, :k, 0)

    l = limiter(rate: {3, :second})
    for _ <- 1..3, do: assert(RateLimit.check(l, :k, 0) == :ok)
    assert {:error, _} = RateLimit.check(l, :k, 0)

    assert_raise KeyError, fn -> RateLimit.new(:x, burst: 5) end

    assert_raise ArgumentError,
                 "rate: {0, :second} is not {count, :second | :minute | :hour}",
                 fn -> RateLimit.new(:x, rate: {0, :second}) end

    assert_raise ArgumentError, ~r/rate: \{1\.5, :second\}/, fn ->
      RateLimit.new(:x, rate: {1.5, :second})
    end

    assert_raise ArgumentError, "burst: 0 is not a positive integer", fn ->
      RateLimit.new(:x, rate: {5, :second}, burst: 0)
    end
  end

  @tag verifies: "rate-new-raises"
  test "a bad rate or burst raises, naming it" do
    assert_raise ArgumentError, ~r/rate: \{0, :second\}/, fn ->
      RateLimit.new(:x, rate: {0, :second})
    end

    assert_raise ArgumentError, ~r/rate: \{5, :day\}/, fn ->
      RateLimit.new(:x, rate: {5, :day})
    end

    assert_raise ArgumentError, ~r/burst: 0/, fn ->
      RateLimit.new(:x, rate: {5, :second}, burst: 0)
    end
  end

  @tag verifies: "rate-window-bound"
  property "over any window, accepted requests never exceed burst plus the rate" do
    check all(
            count <- integer(1..20),
            burst <- integer(1..10),
            gaps <- list_of(integer(0..200_000), min_length: 1, max_length: 80)
          ) do
      l = limiter(rate: {count, :second}, burst: burst)
      times = Enum.scan(gaps, &(&1 + &2))
      accepted = Enum.filter(times, &(RateLimit.check(l, :k, &1) == :ok))
      span = List.last(times) - hd(times)

      assert length(accepted) <= burst + div(span * count, @second) + 1
    end
  end

  @tag verifies: "plug-rate-cas"
  test "concurrent first requests on a new key: one inserts the row, the rest decide again against it" do
    l = limiter(rate: {1, :hour}, burst: 1)

    results =
      1..200
      |> Task.async_stream(fn _ -> RateLimit.check(l, :k, 0) end, max_concurrency: 50)
      |> Enum.map(fn {:ok, r} -> r end)

    assert Enum.count(results, &(&1 == :ok)) == 1
    assert results -- [:ok] == List.duplicate({:error, 3600}, 199)
    assert :ets.lookup(Table, {l.id, :k}) == [{{l.id, :k}, 3600 * @second}]
  end

  @tag verifies: "rate-concurrent"
  test "concurrent callers never take more than the burst" do
    l = limiter(rate: {1, :hour}, burst: 25)

    results =
      1..200
      |> Task.async_stream(fn _ -> RateLimit.check(l, :k, 0) end, max_concurrency: 50)
      |> Enum.map(fn {:ok, r} -> r end)

    assert Enum.count(results, &(&1 == :ok)) == 25
  end

  @tag verifies: "rate-sweep"
  test "the sweep removes idle keys only" do
    l = limiter(rate: {1, :second})
    RateLimit.check(l, :idle, 0)
    RateLimit.check(l, :busy, 10 * @second)

    Table.sweep(5 * @second)

    assert :ets.lookup(Table, {l.id, :idle}) == []
    assert [_] = :ets.lookup(Table, {l.id, :busy})
  end

  describe "the plug" do
    defp run(opts, ip \\ {203, 0, 113, 9}) do
      conn(:get, "/") |> Map.put(:remote_ip, ip) |> RateLimit.call(RateLimit.init(opts))
    end

    @tag verifies: "rate-plug-429"
    test "keys on the client address and answers 429 with Retry-After" do
      opts = [id: make_ref(), rate: {1, :minute}, now: fn -> 0 end]
      refute run(opts).halted

      conn = run(opts)
      assert conn.halted
      assert conn.status == 429
      assert Plug.Conn.get_resp_header(conn, "retry-after") == ["60"]

      refute run(opts, {198, 51, 100, 7}).halted
    end

    @tag verifies: "plug-rate-plug"
    test "an allowed request passes unchanged; a refused one is answered in plain text, or by on_limit after retry-after is set, and halted" do
      opts = [id: make_ref(), rate: {1, :minute}, now: fn -> 0 end]
      conn = Map.put(conn(:get, "/"), :remote_ip, {203, 0, 113, 9})
      assert RateLimit.call(conn, RateLimit.init(opts)) == conn

      conn = run(opts)
      assert conn.halted
      assert conn.state == :sent
      assert conn.status == 429
      assert [content_type] = Plug.Conn.get_resp_header(conn, "content-type")
      assert content_type =~ ~r{^text/plain}
      assert conn.resp_body == "Too many requests; retry in 60 s.\n"

      opts = Keyword.merge(opts, id: make_ref(), on_limit: {__MODULE__, :echo_retry_after})
      refute run(opts).halted
      conn = run(opts)
      assert conn.halted
      assert conn.status == 429
      assert conn.resp_body == "retry-after: 60, wait: 60"

      assert_raise KeyError, fn -> RateLimit.init(rate: {1, :minute}) end
    end

    @tag verifies: "rate-clock-per-call"
    test "the :now function is read at each call, not at init" do
      clock = :counters.new(1, [:atomics])

      opts =
        RateLimit.init(id: make_ref(), rate: {1, :minute}, now: fn -> :counters.get(clock, 1) end)

      conn = Map.put(conn(:get, "/"), :remote_ip, {203, 0, 113, 9})
      refute RateLimit.call(conn, opts).halted

      :counters.add(clock, 1, 60 * @second)
      refute RateLimit.call(conn, opts).halted
    end

    @tag verifies: "plug-rate-clock"
    test "init/1 keeps the clock unread: :monotonic by default, read by call/2" do
      now = fn -> 0 end
      assert RateLimit.init(id: :x, rate: {1, :second}, now: now).now == now

      opts = RateLimit.init(id: make_ref(), rate: {1, :minute})
      assert opts.now == :monotonic

      conn = Map.put(conn(:get, "/"), :remote_ip, {203, 0, 113, 9})
      refute RateLimit.call(conn, opts).halted
      assert RateLimit.call(conn, opts).status == 429
    end

    @tag verifies: "rate-plug-key-on-limit"
    test "takes a key function and an on_limit answer" do
      opts = [
        id: make_ref(),
        rate: {1, :minute},
        now: fn -> 0 end,
        key: {__MODULE__, :by_header},
        on_limit: {__MODULE__, :json_429}
      ]

      refute run(opts).halted
      conn = run(opts)
      assert conn.status == 429
      assert conn.resp_body == ~s({"error":"rate_limited","retry_after":60})
    end
  end

  def by_header(conn), do: Plug.Conn.get_req_header(conn, "x-token")

  def json_429(conn, wait),
    do: Plug.Conn.send_resp(conn, 429, ~s({"error":"rate_limited","retry_after":#{wait}}))

  def echo_retry_after(conn, wait) do
    [retry_after] = Plug.Conn.get_resp_header(conn, "retry-after")
    Plug.Conn.send_resp(conn, 429, "retry-after: #{retry_after}, wait: #{wait}")
  end
end
