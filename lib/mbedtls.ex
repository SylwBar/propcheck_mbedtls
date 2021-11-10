use Bitwise

defmodule MbedTLS do
  @moduledoc false

  @on_load :load_nifs

  def val_compose_key_usage(key_usage_map) do
    key_usage_copy =
      if Map.get(key_usage_map, :copy, false) == true do
        MbedTLS.val_psa_key_usage(:PSA_KEY_USAGE_COPY)
      else
        0
      end

    key_usage_encrypt =
      if Map.get(key_usage_map, :encrypt, false) == true do
        MbedTLS.val_psa_key_usage(:PSA_KEY_USAGE_ENCRYPT)
      else
        0
      end

    key_usage_decrypt =
      if Map.get(key_usage_map, :decrypt, false) == true do
        MbedTLS.val_psa_key_usage(:PSA_KEY_USAGE_DECRYPT)
      else
        0
      end

    key_usage_copy ||| key_usage_encrypt ||| key_usage_decrypt
  end

  def load_nifs do
    nif_filename =
      Application.app_dir(:propcheck_mbedtls, "priv/mbedtls")
      |> to_charlist

    :erlang.load_nif(nif_filename, 0)
  end

  def psa_crypto_init(), do: error_nif()
  def psa_key_attributes_init(), do: error_nif()
  def psa_reset_key_attributes(_attributes), do: error_nif()
  def psa_set_key_id(_attributes, _id), do: error_nif()
  def psa_get_key_id(_attributes), do: error_nif()
  def psa_set_key_bits(_attributes, _bits), do: error_nif()
  def psa_get_key_bits(_attributes), do: error_nif()
  def psa_set_key_usage_flags(_attributes, _flags), do: error_nif()
  def psa_get_key_usage_flags(_attributes), do: error_nif()
  def psa_set_key_algorithm(_attributes, _alg), do: error_nif()
  def psa_get_key_algorithm(_attributes), do: error_nif()
  def psa_set_key_type(_attributes, _type), do: error_nif()
  def psa_get_key_type(_attributes), do: error_nif()
  def psa_get_key_attributes(_key, _attributes), do: error_nif()
  def psa_generate_key(_attributes), do: error_nif()
  def psa_import_key(_attributes, _data), do: error_nif()
  def psa_copy_key(_source_key, _attributes), do: error_nif()
  def psa_generate_random(_output_size), do: error_nif()
  # ----- PSA value converters -----
  def val_psa_key_type(_psa_key_type_atom), do: error_nif()
  def val_psa_key_usage(_psa_key_usage_atom), do: error_nif()
  def val_psa_algorithm(_psa_algorithm_atom), do: error_nif()
  # ----- Other MbedTLS functions -----
  def mbedtls_psa_crypto_free(), do: error_nif()
  # ----- Aux. functions start -----
  def free(_ptr), do: error_nif()
  # ----- Aux. functions end -----

  defp error_nif(), do: IO.puts("Error: mbedtls.so not loaded!")
end
