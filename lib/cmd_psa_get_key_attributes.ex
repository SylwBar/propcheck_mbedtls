use PropCheck

defmodule PSAGetKeyAttributes do
  def pre(state) do
    state.crypto_init == true && length(state.keys) > 0
  end

  def args(state) do
    key_id = let({key_id, _key_data} <- oneof(state.keys), do: key_id)
    [key_id]
  end

  def exec(key_id) do
    tmp_key_attributes_ptr = MbedTLS.psa_key_attributes_init()
    res = MbedTLS.psa_get_key_attributes(key_id, tmp_key_attributes_ptr)
    MbedTLS.free(tmp_key_attributes_ptr)
    res
  end

  def post(_state, _args, result) do
    result == :ok
  end

  def next(state, [_key_id], _result), do: state

  def trace(_state, [key_id], result),
    do: IO.puts("psa_get_key_attributes(#{inspect(key_id, base: :hex)}) => #{result}")
end
