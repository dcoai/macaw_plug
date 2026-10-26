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

  test "keys are independent" do
    l = limiter(rate: {1, :minute})
    assert RateLimit.check(l, :a, 0) == :ok
    assert {:error, 60} = RateLimit.check(l, :a, 0)
    assert RateLimit.check(l, :b, 0) == :ok
  end

  test "the wait is the time until a slot frees, rounded up to a second" do
    l = limiter(rate: {1, :minute})
    assert RateLimit.check(l, :k, 0) == :ok
    assert {:error, 60} = RateLimit.check(l, :k, 0)
    assert {:error, 1} = RateLimit.check(l, :k, 59 * @second + 1)
    assert RateLimit.check(l, :k, 60 * @second) == :ok
  end

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

  test "concurrent callers never take more than the burst" do
    l = limiter(rate: {1, :hour}, burst: 25)

    results =
      1..200
      |> Task.async_stream(fn _ -> RateLimit.check(l, :k, 0) end, max_concurrency: 50)
      |> Enum.map(fn {:ok, r} -> r end)

    assert Enum.count(results, &(&1 == :ok)) == 25
  end

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

    test "keys on the client address and answers 429 with Retry-After" do
      opts = [id: make_ref(), rate: {1, :minute}, now: fn -> 0 end]
      refute run(opts).halted

      conn = run(opts)
      assert conn.halted
      assert conn.status == 429
      assert Plug.Conn.get_resp_header(conn, "retry-after") == ["60"]

      refute run(opts, {198, 51, 100, 7}).halted
    end

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
end
