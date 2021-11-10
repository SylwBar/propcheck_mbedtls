use PropCheck

defmodule PSAKeyAttributesInit do
  def pre(state), do: state.key_attributes_ptr == nil

  def args(_state), do: []

  def exec() do
    MbedTLS.psa_key_attributes_init()
  end

  def post(_state, _args, result), do: result != 0

  def next(state, _args, result),
    do: %{state | key_attributes_ptr: result, key_data: %KeyData{}}

  def trace(_state, _args, result),
    do: IO.puts("psa_key_attributes_init() => #{inspect(result, base: :hex)}")
end
