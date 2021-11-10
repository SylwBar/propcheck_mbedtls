use PropCheck

defmodule PSAGetKeyId do
  def pre(state),
    do: state.key_attributes_ptr != nil && state.key_data.id != nil

  def args(state), do: [state.key_attributes_ptr]

  def exec(key_attributes_ptr), do: MbedTLS.psa_get_key_id(key_attributes_ptr)

  def post(state, _args, result), do: state.key_data.id == result

  def next(state, [_key_attributes_ptr], _result), do: state

  def trace(_state, [_key_attributes_ptr], result),
    do: IO.puts("psa_get_key_id() => #{result}")
end
