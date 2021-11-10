use PropCheck

defmodule PSASetKeyType do
  def pre(state), do: state.key_attributes_ptr != nil

  def args(state), do: [state.key_attributes_ptr, :PSA_KEY_TYPE_AES]

  def exec(key_attributes_ptr, type) do
    type_val = MbedTLS.val_psa_key_type(type)
    MbedTLS.psa_set_key_type(key_attributes_ptr, type_val)
  end

  def post(_state, _args, result), do: result == :ok

  def next(state, [_key_attributes_ptr, type], _result) do
    new_ka = %{state.key_data | type: type}
    %{state | key_data: new_ka}
  end

  def trace(_state, [_key_attributes_ptr, type], result),
    do: IO.puts("psa_set_key_type(#{type}) => #{result}")
end
