use PropCheck

defmodule PSAResetKeyAttributes do
  def pre(state), do: state.key_attributes_ptr != nil

  def args(state), do: [state.key_attributes_ptr]

  def exec(key_attributes_ptr) do
    MbedTLS.psa_reset_key_attributes(key_attributes_ptr)
  end

  def post(_state, _args, result), do: result == :ok

  def next(state, _args, _result),
    do: %{state | key_data: %KeyData{}}

  def trace(_state, _args, result),
    do: IO.puts("psa_reset_key_attributes() => #{result}")
end
