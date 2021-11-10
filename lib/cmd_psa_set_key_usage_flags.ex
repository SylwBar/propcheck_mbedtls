use PropCheck

defmodule PSASetKeyUsageFlags do
  def pre(state), do: state.key_attributes_ptr != nil

  def args(state),
    do: [
      state.key_attributes_ptr,
      [
        encrypt: true,
        decrypt: true,
        copy: boolean()
      ]
    ]

  def exec(key_attributes_ptr, usage_list) do
    usage_val = usage_list |> :maps.from_list() |> MbedTLS.val_compose_key_usage()
    MbedTLS.psa_set_key_usage_flags(key_attributes_ptr, usage_val)
  end

  def post(_state, _args, result), do: result == :ok

  def next(state, [_key_attributes_ptr, usage_list], _result) do
    usage = :maps.from_list(usage_list)
    new_ka = %{state.key_data | usage_flags: usage}
    %{state | key_data: new_ka}
  end

  def trace(_state, [_key_attributes_ptr, usage], result),
    do: IO.puts("psa_set_key_usage_flags(#{inspect(usage)}) => #{result}")
end
