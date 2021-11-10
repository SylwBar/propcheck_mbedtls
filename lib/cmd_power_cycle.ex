use PropCheck

defmodule PowerCycle do
  def pre(state), do: state.crypto_init == true

  def args(state), do: [state]

  def exec(state) do
    if state.key_attributes_ptr != nil do
      MbedTLS.free(state.key_attributes_ptr)
    end

    MbedTLS.mbedtls_psa_crypto_free()
  end

  def post(_state, _args, result), do: result == :ok

  def next(state, _args, _result) do
    persistent_keys = Enum.filter(state.keys, fn {_key_id, key_data} -> key_data.id != nil end)
    %{state | crypto_init: false, key_attributes_ptr: nil, key_data: nil, keys: persistent_keys}
  end

  def trace(_state, _args, result), do: IO.puts("power cycle => #{result}")
end
