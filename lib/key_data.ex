defmodule KeyData do
  defstruct id: nil, type: nil, bits: nil, algorithm: nil, usage_flags: nil

  def valid_key_data(key_params) do
    valid_key(key_params.type, key_params.bits, key_params.algorithm, key_params.usage_flags)
  end

  defp valid_key(:PSA_KEY_TYPE_AES, 128, :PSA_ALG_CBC_NO_PADDING, %{
         encrypt: true,
         decrypt: true
       }),
       do: true

  defp valid_key(_type, _bits, _algorithm, _usage_flags), do: false
end
