use PropCheck

defmodule PSAGenerateRandom do
  defmodule Success do
    def pre(state), do: state.crypto_init == true

    def args(_state), do: [non_neg_integer()]

    def exec(output_size), do: MbedTLS.psa_generate_random(output_size)

    def post(_state, [output_size], result), do: byte_size(result) == output_size

    def next(state, _args, _result), do: state

    def trace(_state, [output_size], result),
      do: IO.puts("psa_generate_random(#{output_size}) => binary:#{byte_size(result)}")
  end

  defmodule Fail do
    def pre(state), do: state.crypto_init == false

    def args(_state), do: [non_neg_integer()]

    def exec(output_size), do: MbedTLS.psa_generate_random(output_size)

    def post(_state, [_output_size], result), do: result == {:error, :PSA_ERROR_BAD_STATE}

    def next(state, _args, _result), do: state

    def trace(_state, [output_size], result),
      do: IO.puts("psa_generate_random(#{output_size}) => #{inspect(result)}")
  end
end
