defmodule Macaw.Plug.RateLimit.Table do
  @moduledoc """
  Owns `Macaw.Plug.RateLimit`'s ETS table and sweeps it.

  A key whose theoretical arrival time has passed has its full burst again,
  so it is the same as an absent key, and the sweep deletes it. The sweep
  runs every `:sweep_every` milliseconds (default one minute).
  """

  use GenServer

  @default_sweep 60_000

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Deletes every key idle at `now` (monotonic microseconds); returns how many."
  @spec sweep(integer()) :: non_neg_integer()
  def sweep(now \\ System.monotonic_time(:microsecond)),
    do: :ets.select_delete(__MODULE__, [{{:_, :"$1"}, [{:<, :"$1", now}], [true]}])

  @impl true
  def init(opts) do
    :ets.new(__MODULE__, [
      :named_table,
      :public,
      :set,
      write_concurrency: true,
      read_concurrency: true
    ])

    every = Keyword.get(opts, :sweep_every, @default_sweep)
    Process.send_after(self(), :sweep, every)
    {:ok, every}
  end

  @impl true
  def handle_info(:sweep, every) do
    sweep()
    Process.send_after(self(), :sweep, every)
    {:noreply, every}
  end
end
