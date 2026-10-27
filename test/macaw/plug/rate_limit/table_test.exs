defmodule Macaw.Plug.RateLimit.TableTest do
  # Not async: these tests start, stop and restart the one named table, which
  # Macaw.Plug.RateLimitTest's async tests share while they run. ExUnit runs
  # sync modules after every async one, so the table is never pulled from
  # under them.
  use ExUnit.Case, async: false

  alias Macaw.Plug.RateLimit
  alias Macaw.Plug.RateLimit.Table

  @second 1_000_000

  defp limiter(opts), do: RateLimit.new(make_ref(), opts)

  @tag verifies: "plug-rate-check"
  test "check needs the table running; without it, it raises" do
    refute Process.whereis(Table)
    l = limiter(rate: {1, :second})
    assert_raise ArgumentError, fn -> RateLimit.check(l, :k, 0) end

    # started by start_link/0, its defaults
    start_supervised!(%{id: Table, start: {Table, :start_link, []}})
    assert RateLimit.check(l, :k, 0) == :ok
  end

  @tag verifies: "plug-rate-table"
  test "the table: named, public, a set with read and write concurrency; a sweep counts what it deletes; a restart starts empty" do
    # started by start_link/0, its defaults
    pid = start_supervised!(%{id: Table, start: {Table, :start_link, []}})

    assert Process.whereis(Table) == pid
    assert :ets.info(Table, :owner) == pid
    assert :ets.info(Table, :named_table)
    assert :ets.info(Table, :protection) == :public
    assert :ets.info(Table, :type) == :set
    assert :ets.info(Table, :read_concurrency)
    assert :ets.info(Table, :write_concurrency)

    # the sweep runs every minute by default
    assert :sys.get_state(Table) == 60_000

    l = limiter(rate: {1, :second})
    for key <- [:a, :b], do: RateLimit.check(l, key, 0)
    RateLimit.check(l, :c, 10 * @second)

    assert Table.sweep(5 * @second) == 2
    assert Table.sweep(5 * @second) == 0

    # a swept key is decided as a key never seen: allowed, at any time
    assert RateLimit.check(l, :a, 0) == :ok

    stop_supervised!(Table)
    start_supervised!(Table)
    assert :ets.info(Table, :size) == 0

    # sweep/0 sweeps at the clock's now (on the fresh table, where every row is relative to it)
    now = System.monotonic_time(:microsecond)
    RateLimit.check(l, :passed, now - 10 * @second)
    RateLimit.check(l, :ahead, now + 10 * @second)
    assert Table.sweep() == 1
    assert :ets.lookup(Table, {l.id, :passed}) == []
    assert [_] = :ets.lookup(Table, {l.id, :ahead})

    assert RateLimit.check(l, :c, 10 * @second) == :ok
  end

  @tag verifies: "plug-rate-table"
  test "the table sweeps itself every :sweep_every milliseconds" do
    start_supervised!({Table, sweep_every: 10})

    l = limiter(rate: {1, :second})
    RateLimit.check(l, :idle, System.monotonic_time(:microsecond) - 10 * @second)
    assert [_] = :ets.lookup(Table, {l.id, :idle})

    assert swept?({l.id, :idle}, 100)
  end

  # Polls for at most `tries` × 10 ms, so a slow machine fails the test rather than hangs it.
  defp swept?(_row_key, 0), do: false

  defp swept?(row_key, tries) do
    if :ets.lookup(Table, row_key) == [] do
      true
    else
      Process.sleep(10)
      swept?(row_key, tries - 1)
    end
  end
end
