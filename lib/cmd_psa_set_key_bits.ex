use PropCheck

defmodule PSASetKeyBits do
  def pre(state), do: state.key_attributes_ptr != nil

  def args(state), do: [state.key_attributes_ptr, 128]

  def exec(key_attributes_ptr, bits), do: MbedTLS.psa_set_key_bits(key_attributes_ptr, bits)

  def post(_state, _args, result), do: result == :ok

  def next(state, [_key_attributes_ptr, bits], _result) do
    new_ka = %{state.key_data | bits: bits}
    %{state | key_data: new_ka}
  end

  def trace(_state, [_key_attributes_ptr, bits], result),
    do: IO.puts("psa_set_key_bits(#{bits}) => #{result}")
end
