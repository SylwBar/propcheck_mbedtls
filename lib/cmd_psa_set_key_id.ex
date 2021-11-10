use PropCheck

defmodule PSASetKeyId do
  def pre(state), do: state.key_attributes_ptr != nil

  def args(state), do: [state.key_attributes_ptr, pos_integer()]

  def exec(key_attributes_ptr, id), do: MbedTLS.psa_set_key_id(key_attributes_ptr, id)

  def post(_state, _args, result), do: result == :ok

  def next(state, [_key_attributes_ptr, id], _result) do
    new_ka = %{state.key_data | id: id}
    %{state | key_data: new_ka}
  end

  def trace(_state, [_key_attributes_ptr, id], result),
    do: IO.puts("psa_set_key_id(#{id}) => #{result}")
end
