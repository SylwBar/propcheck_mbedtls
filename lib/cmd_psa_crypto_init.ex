use PropCheck

defmodule PSACryptoInit do
  def pre(state), do: state.crypto_init == false

  def args(_state), do: []

  def exec(), do: MbedTLS.psa_crypto_init()

  def post(_state, _args, result), do: result == :ok

  def next(state, _args, _result), do: %{state | crypto_init: true}

  def trace(_state, _args, result), do: IO.puts("psa_crypto_init() => #{result}")
end
