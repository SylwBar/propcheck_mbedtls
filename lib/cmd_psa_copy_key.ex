use PropCheck

defmodule PSACopyKey do
  defmodule Volatile.Success do
    def pre(state) do
      state.crypto_init == true && state.key_data != nil && length(state.keys) > 0 &&
        state.key_data.id == nil && KeyData.valid_key_data(state.key_data)
    end

    def args(state) do
      source_key_id = let({key_id, _key_data} <- oneof(state.keys), do: key_id)
      [source_key_id, state.key_attributes_ptr]
    end

    def pre(state, [source_key, _key_attributes_ptr]) do
      {_key_id, key_data} = Enum.find(state.keys, fn {key_id, _data} -> key_id == source_key end)
      key_data.usage_flags.copy
    end

    def exec(source_key, key_attributes_ptr) do
      MbedTLS.psa_copy_key(source_key, key_attributes_ptr)
    end

    def post(_state, _args, {:error, _}), do: false
    def post(_state, _args, _), do: true

    def next(state, [_source_key, _key_attributes_ptr], res_key_id) do
      %{state | keys: [{res_key_id, state.key_data} | state.keys]}
    end

    def trace(_state, [source_key, _key_data], result) do
      IO.puts(
        "psa_copy_key(#{inspect(source_key, base: :hex)}) => #{inspect(result, base: :hex)} [volatile]"
      )
    end
  end

  defmodule Persistent.Success do
    def pre(state) do
      state.crypto_init == true && state.key_data != nil && length(state.keys) > 0 &&
        state.key_data.id != nil && KeyData.valid_key_data(state.key_data) &&
        List.keyfind(state.keys, state.key_data.id, 0) == nil
    end

    def args(state) do
      source_key_id = let({key_id, _key_data} <- oneof(state.keys), do: key_id)
      [source_key_id, state.key_attributes_ptr]
    end

    def pre(state, [source_key, _key_attributes_ptr]) do
      {_key_id, key_data} = Enum.find(state.keys, fn {key_id, _data} -> key_id == source_key end)
      key_data.usage_flags.copy
    end

    def exec(source_key, key_attributes_ptr) do
      MbedTLS.psa_copy_key(source_key, key_attributes_ptr)
    end

    def post(_state, _args, {:error, _}), do: false
    def post(_state, _args, _), do: true

    def next(state, [_source_key, _key_attributes_ptr], _res_key_id) do
      key_id = state.key_data.id
      %{state | keys: [{key_id, state.key_data} | state.keys]}
    end

    def trace(_state, [source_key, _key_data], result) do
      IO.puts(
        "psa_copy_key(#{inspect(source_key, base: :hex)}) => #{inspect(result, base: :hex)} [persistent]"
      )
    end
  end
end
