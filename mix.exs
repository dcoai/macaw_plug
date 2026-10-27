defmodule Macaw.Plug.MixProject do
  use Mix.Project

  @version "0.1.1"

  def project do
    [
      app: :macaw_plug,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "Request guards for Plug hosts: the client address behind trusted proxies, rate limiting, security headers.",
      package: [licenses: ["MIT"]],
      docs: [main: "readme", extras: ["README.md"]]
    ]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps do
    [
      {:plug, "~> 1.16"},
      {:telemetry, "~> 1.2"},
      {:stream_data, "~> 1.1", only: :test}
    ]
  end
end
