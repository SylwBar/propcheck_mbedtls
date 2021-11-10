use PropCheck

defmodule PSAGenerateKey do
  defmodule Volatile.Success do
    def pre(state),
      do:
        state.crypto_init == true && state.key_data != nil &&
          state.key_data.id == nil && KeyData.valid_key_data(state.key_data)

    def args(state), do: [state.key_attributes_ptr]

    def exec(key_attributes_ptr), do: MbedTLS.psa_generate_key(key_attributes_ptr)

    def post(_state, _args, {:error, _}), do: false
    def post(_state, _args, _), do: true

    def next(state, [_key_attributes_ptr], res_key_id) do
      %{state | keys: [{res_key_id, state.key_data} | state.keys]}
    end

    def trace(_state, [_key_attributes], result),
      do: IO.puts("psa_generate_key() => #{inspect(result, base: :hex)} [volatile]")
  end

  defmodule Persistent.Success do
    def pre(state),
      do:
        state.crypto_init == true && state.key_data != nil &&
          state.key_data.id != nil && KeyData.valid_key_data(state.key_data) &&
          List.keyfind(state.keys, state.key_data.id, 0) == nil

    def args(state), do: [state.key_attributes_ptr]

    def exec(key_attributes_ptr), do: MbedTLS.psa_generate_key(key_attributes_ptr)

    def post(_state, _args, {:error, _}), do: false
    def post(state, _args, res_key_id), do: state.key_data.id == res_key_id

    def next(state, [_key_attributes_ptr], _res_key_id) do
      key_id = state.key_data.id
      %{state | keys: [{key_id, state.key_data} | state.keys]}
    end

    def trace(_state, [_key_attributes], result),
      do: IO.puts("psa_generate_key() => #{inspect(result)} [persistent]")
  end

  defmodule Persistent.PSA_ERROR_ALREADY_EXISTS do
    def pre(state),
      do:
        state.crypto_init == true && state.key_data != nil &&
          state.key_data.id != nil && KeyData.valid_key_data(state.key_data) &&
          List.keyfind(state.keys, state.key_data.id, 0) != nil

    def args(state), do: [state.key_attributes_ptr]

    def exec(key_attributes_ptr), do: MbedTLS.psa_generate_key(key_attributes_ptr)

    def post(_state, _args, {:error, :PSA_ERROR_ALREADY_EXISTS}), do: true
    def post(_state, _args, _), do: false

    def next(state, [_key_attributes_ptr], _res_key_id), do: state

    def trace(_state, [_key_attributes], result),
      do: IO.puts("psa_generate_key() => #{inspect(result)}")
  end
end
