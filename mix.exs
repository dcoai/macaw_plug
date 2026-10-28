defmodule Macaw.Plug.MixProject do
  use Mix.Project

  @source_url "https://github.com/dcoai/macaw_plug"
  @version "0.1.3"

  def project do
    [
      app: :macaw_plug,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "Request guards for Plug hosts: the client address behind trusted proxies, rate limiting, security headers.",
      source_url: @source_url,
      package: package(),
      docs: [main: "readme", extras: ["README.md", "CHANGELOG.md"], source_ref: "v#{@version}"]
    ]
  end

  def application, do: [extra_applications: [:logger]]

  # Published on Hex from its public home, mirrored from GitLab (dco-tek/macaw/macaw#155).
  defp package do
    [
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "https://hexdocs.pm/macaw_plug/changelog.html"
      },
      files: ~w(lib spec mix.exs README.md LICENSE CHANGELOG.md .formatter.exs)
    ]
  end

  defp deps do
    [
      {:plug, "~> 1.16"},
      {:telemetry, "~> 1.2"},
      {:stream_data, "~> 1.1", only: :test},
      # Docs for Hex (macaw_compose#155); dev only.
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      # Spec, tests and code kept aligned (macaw_compose spec/00 §4.1); dev/test only.
      {:surfex, "~> 0.10.0", only: [:dev, :test], runtime: false}
    ]
  end
end
