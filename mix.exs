defmodule PCMbedTLS.MixProject do
  use Mix.Project

  def project do
    [
      app: :propcheck_mbedtls,
      version: "0.1.0",
      elixir: "~> 1.11",
      compilers: [:elixir_make] ++ Mix.compilers(),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:propcheck, "~> 1.4"},
      {:elixir_make, "~> 0.6"}
    ]
  end
end
