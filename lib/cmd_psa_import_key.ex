use PropCheck

defmodule PSAImportKey do
  defmodule Volatile.Success do
    def pre(state),
      do:
        state.crypto_init == true && state.key_data != nil &&
          state.key_data.id == nil && KeyData.valid_key_data(state.key_data)

    def args(state),
      do: [state.key_attributes_ptr, <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>]

    def exec(key_attributes_ptr, data), do: MbedTLS.psa_import_key(key_attributes_ptr, data)

    def post(_state, _args, {:error, _}), do: false
    def post(_state, _args, _), do: true

    def next(state, [_key_attributes_ptr, _data], res_key_id) do
      %{state | keys: [{res_key_id, state.key_data} | state.keys]}
    end

    def trace(_state, [_key_attributes, data], result),
      do: IO.puts("psa_import_key(#{inspect(data)}) => #{inspect(result, base: :hex)} [volatile]")
  end
end
