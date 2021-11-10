use PropCheck

defmodule PSASetKeyAlgorithm do
  def pre(state), do: state.key_attributes_ptr != nil

  def args(state), do: [state.key_attributes_ptr, :PSA_ALG_CBC_NO_PADDING]

  def exec(key_attributes_ptr, alg) do
    alg_val = MbedTLS.val_psa_algorithm(alg)
    MbedTLS.psa_set_key_algorithm(key_attributes_ptr, alg_val)
  end

  def post(_state, _args, result), do: result == :ok

  def next(state, [_key_attributes_ptr, alg], _result) do
    new_ka = %{state.key_data | algorithm: alg}
    %{state | key_data: new_ka}
  end

  def trace(_state, [_key_attributes_ptr, alg], result),
    do: IO.puts("psa_set_key_algorithm(#{alg}) => #{result}")
end
